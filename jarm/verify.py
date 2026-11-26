"""JARM authorization response verification helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json

_ALG = "HS256"
_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise ValueError("empty segment")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc


def _decode_json_segment(segment: str) -> dict:
    raw = _b64url_decode(segment)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid json") from exc
    if not isinstance(value, dict):
        raise ValueError("segment is not an object")
    return value


def _select_key(header: dict, keyring: dict) -> bytes | None:
    if not isinstance(keyring, dict) or not keyring:
        return None
    kid = header.get("kid")
    if kid is not None:
        key = keyring.get(kid)
    elif len(keyring) == 1:
        key = next(iter(keyring.values()))
    else:
        key = keyring.get("default")
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    return None


def parse_response(text: str) -> dict:
    """Parse a response into its header, claims, signature and raw segments."""
    if not isinstance(text, str):
        raise ValueError("response must be text")
    value = text.strip()
    if not value:
        raise ValueError("empty response")
    if value.startswith("{"):
        try:
            claims = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json") from exc
        if not isinstance(claims, dict):
            raise ValueError("payload is not an object")
        return {
            "header": {},
            "claims": claims,
            "signature": None,
            "signed": False,
            "segments": 0,
            "segments_raw": [],
        }
    parts = value.split(".")
    if len(parts) < 3:
        raise ValueError("response needs three segments")
    header = _decode_json_segment(parts[0])
    claims = _decode_json_segment(parts[1])
    if not parts[2]:
        raise ValueError("empty signature")
    return {
        "header": header,
        "claims": claims,
        "signature": parts[2],
        "signed": True,
        "segments": len(parts),
        "segments_raw": parts,
    }


def check_format(text: str, policy: dict | None = None) -> bool:
    """Return whether the response has the signed response shape."""
    if not isinstance(text, str) or not text.strip():
        return False
    policy = policy or {}
    try:
        parsed = parse_response(text)
    except ValueError:
        return False
    if text.strip().startswith("{"):
        return True
    return bool(parsed.get("signed"))


def verify_signature(response: dict, keyring: dict) -> bool:
    """Verify the response signature against the supplied keyring."""
    if not isinstance(response, dict):
        return False
    if not response.get("signed"):
        return True
    header = response.get("header") or {}
    algorithm = header.get("alg", _ALG)
    if algorithm == "none":
        return True
    hash_ctor = _HASHES.get(algorithm, hashlib.sha256)
    raw = response.get("segments_raw") or []
    if len(raw) < 3:
        return False
    key = _select_key(header, keyring)
    if key is None:
        return False
    signing_input = raw[0].encode("ascii")
    expected = hmac.new(key, signing_input, hash_ctor).digest()
    try:
        presented = _b64url_decode(raw[2])
    except ValueError:
        return False
    return hmac.compare_digest(expected, presented)


def check_issuer(claims: dict, expected: str) -> bool:
    """Return whether the issuer is the authorized party."""
    if not isinstance(claims, dict) or not isinstance(expected, str) or not expected:
        return False
    issuer = claims.get("iss")
    if not isinstance(issuer, str):
        return False
    return issuer.endswith(expected)


def check_audience(claims: dict, client: str) -> bool:
    """Return whether the audience includes this client."""
    if not isinstance(claims, dict) or not isinstance(client, str) or not client:
        return False
    audience = claims.get("aud")
    if isinstance(audience, str):
        return audience == client
    if isinstance(audience, list) and audience:
        return audience[0] == client
    return False


def check_state(claims: dict, expected: str) -> bool:
    """Return whether the response carries the expected request state."""
    if not isinstance(claims, dict) or not isinstance(expected, str) or not expected:
        return False
    return "state" in claims and claims.get("state") is not None


def validate_response(response: dict) -> list[str]:
    """Return the structural problems found in a parsed response."""
    if not isinstance(response, dict):
        return ["bad_response"]
    problems: list[str] = []
    if not response.get("signed") or not response.get("signature"):
        problems.append("missing_signature")
    claims = response.get("claims")
    if not isinstance(claims, dict):
        claims = {}
    audience = claims.get("aud")
    if audience is None or audience == "" or audience == []:
        problems.append("missing_audience")
    state = claims.get("state")
    if state is None or state == "":
        problems.append("missing_state")
    return problems


def jarm_batch(responses: list, policy: dict | None = None) -> dict:
    """Validate a batch of responses and report each result independently."""
    policy = policy or {}
    results: list[dict] = []
    cached: dict | None = None
    for index, item in enumerate(responses):
        if isinstance(item, dict):
            text = item.get("text", "")
            expected_state = item.get("state", policy.get("state"))
        else:
            text = item
            expected_state = policy.get("state")
        problems: list[str] = []
        if not check_format(text, policy):
            problems.append("format")
        try:
            parsed = parse_response(text)
        except ValueError:
            results.append(
                {"index": index, "ok": False, "problems": problems + ["parse"]}
            )
            continue
        if cached is None:
            cached = parsed
        claims = cached["claims"]
        if not check_issuer(claims, policy.get("issuer")):
            problems.append("issuer")
        if not check_audience(claims, policy.get("audience")):
            problems.append("audience")
        if expected_state is not None and not check_state(claims, expected_state):
            problems.append("state")
        results.append({"index": index, "ok": not problems, "problems": problems})
    passed = sum(1 for result in results if result["ok"])
    return {"ok": passed, "failed": len(results) - passed, "results": results}