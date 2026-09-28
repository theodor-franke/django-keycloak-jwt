from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from django.test import override_settings

from keycloak_jwt import validation
from keycloak_jwt.exceptions import TokenExpired, TokenInvalid

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _flip_middle_char(segment: str) -> str:
    # Flip a character in the middle, not the last one or two: base64url's
    # final partial group can have "don't care" bits that decode to the
    # same bytes, making a last-character tamper a no-op.
    middle = len(segment) // 2
    flipped_char = "A" if segment[middle] != "A" else "B"
    return segment[:middle] + flipped_char + segment[middle + 1 :]


@pytest.fixture(autouse=True)
def _kc_settings(jwks_server: JWKSServer, signer: Signer):
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "JWKS_URL": jwks_server.url,
            "LEEWAY": 10,
        }
    ):
        jwks_server.set_keys(signer.jwk)
        yield


def test_valid_token_returns_claims(make_token: TokenFactory) -> None:
    token = make_token()
    claims = validation.validate_token(token)
    assert claims["sub"] == "11111111-1111-1111-1111-111111111111"
    assert claims["preferred_username"] == "alice"


def test_expired_token_raises_token_expired(make_token: TokenFactory) -> None:
    now = int(time.time())
    token = make_token(claims={"iat": now - 1000, "exp": now - 100})
    with pytest.raises(TokenExpired):
        validation.validate_token(token)


def test_nbf_in_future_rejected(make_token: TokenFactory) -> None:
    now = int(time.time())
    token = make_token(claims={"nbf": now + 1000})
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_nbf_within_leeway_accepted(make_token: TokenFactory) -> None:
    now = int(time.time())
    token = make_token(claims={"nbf": now + 5})
    validation.validate_token(token)


def test_wrong_issuer_rejected(make_token: TokenFactory) -> None:
    token = make_token(claims={"iss": "https://evil.example/realms/test"})
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_wrong_audience_rejected(make_token: TokenFactory) -> None:
    token = make_token(claims={"aud": "someone-else"})
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_missing_audience_rejected(signer: Signer) -> None:
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": ISSUER,
            "sub": "x",
            "iat": now,
            "exp": now + 300,
            "typ": "Bearer",
        },
        key=signer.private_key,
        algorithm="RS256",
        headers={"kid": signer.kid},
    )
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_audience_list_containing_ours_accepted(make_token: TokenFactory) -> None:
    token = make_token(claims={"aud": ["other-client", AUDIENCE]})
    validation.validate_token(token)


def test_typ_id_rejected(make_token: TokenFactory) -> None:
    token = make_token(claims={"typ": "ID"})
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_typ_refresh_rejected(make_token: TokenFactory) -> None:
    token = make_token(claims={"typ": "Refresh"})
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_azp_not_in_allowed_list_rejected(
    make_token: TokenFactory, jwks_server: JWKSServer, signer: Signer
) -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "JWKS_URL": jwks_server.url,
            "ALLOWED_AZP": ["frontend"],
        }
    ):
        token = make_token(claims={"azp": "some-other-client"})
        with pytest.raises(TokenInvalid):
            validation.validate_token(token)


def test_azp_in_allowed_list_accepted(
    make_token: TokenFactory, jwks_server: JWKSServer, signer: Signer
) -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "JWKS_URL": jwks_server.url,
            "ALLOWED_AZP": ["frontend"],
        }
    ):
        token = make_token(claims={"azp": "frontend"})
        validation.validate_token(token)


def test_alg_none_rejected(signer: Signer) -> None:
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "x",
            "iat": now,
            "exp": now + 300,
            "typ": "Bearer",
        },
        key=None,
        algorithm="none",
        headers={"kid": signer.kid},
    )
    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_algorithm_confusion_hs256_with_rsa_public_key_rejected(signer: Signer) -> None:
    # Forge the classic RS256->HS256 confusion attack by hand: PyJWT's own
    # encode() now refuses to use a PEM-formatted key as an HMAC secret, but
    # a real attacker isn't bound by that -- they construct the JWS bytes
    # directly. This must still be rejected, and by the alg allowlist check
    # (before any key lookup), not by luck.
    public_pem = signer.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": signer.kid}
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "x",
        "iat": now,
        "exp": now + 300,
        "typ": "Bearer",
    }
    signing_input = (
        f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    ).encode()
    signature = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
    token = f"{signing_input.decode()}.{_b64url(signature)}"

    with pytest.raises(TokenInvalid):
        validation.validate_token(token)


def test_tampered_payload_rejected(make_token: TokenFactory) -> None:
    token = make_token()
    header_b64, payload_b64, sig_b64 = token.split(".")
    tampered_payload = _flip_middle_char(payload_b64)
    tampered = f"{header_b64}.{tampered_payload}.{sig_b64}"
    with pytest.raises(TokenInvalid):
        validation.validate_token(tampered)


def test_tampered_signature_rejected(make_token: TokenFactory) -> None:
    token = make_token()
    header_b64, payload_b64, sig_b64 = token.split(".")
    tampered_sig = _flip_middle_char(sig_b64)
    tampered = f"{header_b64}.{payload_b64}.{tampered_sig}"
    with pytest.raises(TokenInvalid):
        validation.validate_token(tampered)
