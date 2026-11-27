"""JARM authorization response verification helpers.

Verification fails closed: every authorization response must be a signed
JWT/JARM compact token, the MAC must cover both header and payload, the
issuer/audience/state claims must match the local policy, and batch entries
are judged independently.
"""

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
    """Parse a response into its header, claims, signature and raw segments.

    Signed responses use the compact three-segment serialization
    ``header.payload.signature``; anything with fewer or more segments is
    rejected. Plain JSON is parsed for inspection but marked unsigned.
    """
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
    if len(parts) != 3:
        raise ValueError("response needs exactly three segments")
    header = _decode_json_segment(parts[0])
    claims = _decode_json_segment(parts[1])
    if not parts[2]:
        raise ValueError("empty signature")
    return {
        "header": header,
        "claims": claims,
        "signature": parts[2],
        "signed": True,
        "segments": 3,
        "segments_raw": parts,
    }


def check_format(text: str, policy: dict | None = None) -> bool:
    """Return whether the response has the required signed response shape.

    Every authorization response must be signed, so a plaintext JSON body
    never passes -- regardless of the supplied policy.
    """
    if not isinstance(text, str) or not text.strip():
        return False
    try:
        parsed = parse_response(text)
    except ValueError:
        return False
    return bool(parsed.get("signed")) and bool(parsed.get("signature"))


def verify_signature(response: dict, keyring: dict) -> bool:
    """Verify the response signature against the supplied keyring.

    The MAC must cover the complete signing input, i.e. both the header and
    the payload segments (``header.payload``). Verification fails closed:
    unsigned/plaintext responses, the ``none`` algorithm and its case
    variants, unknown algorithms, missing keys and any MAC mismatch are
    all rejected.
    """
    if not isinstance(response, dict):
        return False
    if not response.get("signed") or not response.get("signature"):
        return False
    header = response.get("header") or {}
    if not isinstance(header, dict):
        return False
    algorithm = header.get("alg", _ALG)
    hash_ctor = _HASHES.get(algorithm) if isinstance(algorithm, str) else None
    if hash_ctor is None:
        # Rejects "none" (and its case variants) as well as any algorithm
        # we cannot actually verify -- never silently downgrade to sha256.
        return False
    raw = response.get("segments_raw") or []
    if not isinstance(raw, (list, tuple)) or len(raw) != 3:
        return False
    key = _select_key(header, keyring if isinstance(keyring, dict) else {})
    if key is None:
        return False
    try:
        signing_input = (raw[0] + "." + raw[1]).encode("ascii")
        expected = hmac.new(key, signing_input, hash_ctor).digest()
        presented = _b64url_decode(raw[2])
    except (ValueError, TypeError, binascii.Error):
        return False
    return hmac.compare_digest(expected, presented)


def check_issuer(claims: dict, expected: str) -> bool:
    """Return whether the issuer is exactly the authorized party."""
    if not isinstance(claims, dict) or not isinstance(expected, str) or not expected:
        return False
    issuer = claims.get("iss")
    if not isinstance(issuer, str):
        return False
    return issuer == expected


def check_audience(claims: dict, client: str) -> bool:
    """Return whether the audience includes this client.

    A single string audience must equal the client; a list audience is
    checked by membership so the client is accepted at any position.
    """
    if not isinstance(claims, dict) or not isinstance(client, str) or not client:
        return False
    audience = claims.get("aud")
    if isinstance(audience, str):
        return audience == client
    if isinstance(audience, list):
        return client in audience
    return False


def check_state(claims: dict, expected: str) -> bool:
    """Return whether the response carries exactly this request's nonce."""
    if not isinstance(claims, dict) or not isinstance(expected, str) or not expected:
        return False
    state = claims.get("state")
    if not isinstance(state, str):
        return False
    return state == expected


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
    """Validate a batch of responses and report each result independently.

    Every entry is parsed, signature-verified and judged against its own
    claims and request nonce. The parse or verdict of one entry never
    influences another. An entry whose signature cannot be verified is
    always rejected.
    """
    policy = policy or {}
    keyring = policy.get("keyring") or {}
    results: list[dict] = []
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
        if not verify_signature(parsed, keyring):
            problems.append("signature")
        claims = parsed.get("claims")
        if not isinstance(claims, dict):
            claims = {}
        issuer = policy.get("issuer")
        if issuer is not None and not check_issuer(claims, issuer):
            problems.append("issuer")
        audience = policy.get("audience")
        if audience is not None and not check_audience(claims, audience):
            problems.append("audience")
        if expected_state is not None and not check_state(claims, expected_state):
            problems.append("state")
        results.append({"index": index, "ok": not problems, "problems": problems})
    passed = sum(1 for result in results if result["ok"])
    return {"ok": passed, "failed": len(results) - passed, "results": results}
