"""Public tests for JARM authorization response verification."""

import json

import pytest

from jarm import (
    check_audience,
    check_format,
    jarm_batch,
    parse_response,
    verify_signature,
)


def test_parse_response_requires_exactly_three_segments(make_token, claims, key):
    token = make_token(claims, key)
    with pytest.raises(ValueError):
        parse_response(token + ".extra")


def test_check_format_rejects_plaintext_response(claims):
    plaintext = json.dumps(claims)
    assert check_format(plaintext, {"require_signed": True}) is False


def test_verify_signature_rejects_tampered_payload(make_token, claims, key):
    tampered = dict(claims)
    tampered["state"] = "attacker-state"
    token = make_token(tampered, key, cover="header")
    response = parse_response(token)
    assert verify_signature(response, {"primary": key}) is False


def test_check_audience_finds_client_beyond_first_entry():
    claims = {"aud": ["client-9", "client-7"]}
    assert check_audience(claims, "client-7") is True


def test_batch_keeps_signed_responses_independent(make_token, claims, key, policy):
    good = make_token(claims, key)
    forged = make_token(claims, key + "-other")
    result = jarm_batch(
        [
            {"text": good, "state": "nonce-1"},
            {"text": forged, "state": "nonce-1"},
        ],
        policy,
    )
    assert result["results"][0]["ok"] is True
    assert result["results"][1]["ok"] is False