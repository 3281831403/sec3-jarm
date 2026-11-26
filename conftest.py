"""Test support for the JARM response verification exercise."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_part(value: dict) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b64url(raw)


@pytest.fixture
def make_token():
    """Build a signed response; cover can be full, header or none."""

    def build(claims, key, header=None, cover="full"):
        header = header or {"alg": "HS256", "typ": "JARM", "kid": "primary"}
        head = encode_part(header)
        payload = encode_part(claims)
        if cover == "header":
            material = head.encode("ascii")
        elif cover == "none":
            material = b""
        else:
            material = (head + "." + payload).encode("ascii")
        mac = hmac.new(key.encode("utf-8"), material, hashlib.sha256).digest()
        return head + "." + payload + "." + b64url(mac)

    return build


@pytest.fixture
def key():
    return "public-test-key"


@pytest.fixture
def claims():
    return {
        "iss": "auth.example.com",
        "aud": ["client-7", "client-9"],
        "state": "nonce-1",
        "sub": "alice",
    }


@pytest.fixture
def policy(key):
    return {
        "require_signed": True,
        "keyring": {"primary": key},
        "issuer": "auth.example.com",
        "audience": "client-7",
    }