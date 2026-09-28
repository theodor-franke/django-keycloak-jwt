from __future__ import annotations

import base64
import hashlib
import time
from typing import Any

import pytest
from django.test import override_settings

from django_keycloak_jwt.admin_login import oidc
from django_keycloak_jwt.exceptions import TokenExpired, TokenInvalid

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory

ADMIN_CLIENT_ID = "django-admin"


@pytest.fixture(autouse=True)
def _kc_settings(jwks_server: JWKSServer, signer: Signer):
    with (
        override_settings(
            KEYCLOAK_JWT={
                "ISSUER": ISSUER,
                "AUDIENCE": AUDIENCE,
                "JWKS_URL": jwks_server.url,
                "ROLE_CLIENT": "api",
            },
            KEYCLOAK_JWT_ADMIN={"CLIENT_ID": ADMIN_CLIENT_ID},
        ),
    ):
        jwks_server.set_keys(signer.jwk)
        yield


def _id_token(make_token: TokenFactory, **claim_overrides: Any) -> str:
    claims = {
        "aud": ADMIN_CLIENT_ID,
        "azp": ADMIN_CLIENT_ID,
        "typ": "ID",
        **claim_overrides,
    }
    return make_token(claims=claims)


def test_generate_pkce_pair_matches_s256() -> None:
    verifier, challenge = oidc.generate_pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    expected = expected.rstrip(b"=").decode("ascii")
    assert challenge == expected
    assert len(verifier) >= 43


def test_generate_state_is_random() -> None:
    assert oidc.generate_state() != oidc.generate_state()


def test_build_authorization_url_contains_expected_params() -> None:
    url = oidc.build_authorization_url(
        endpoints={"authorization_endpoint": "https://kc.example.test/auth"},
        client_id=ADMIN_CLIENT_ID,
        redirect_uri="https://django.example.test/admin-login/callback/",
        state="the-state",
        code_challenge="the-challenge",
        scope="openid",
    )
    assert url.startswith("https://kc.example.test/auth?")
    assert "client_id=django-admin" in url
    assert "state=the-state" in url
    assert "code_challenge=the-challenge" in url
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url


def test_resolve_endpoints_prefers_explicit_settings() -> None:
    with override_settings(
        KEYCLOAK_JWT_ADMIN={
            "CLIENT_ID": ADMIN_CLIENT_ID,
            "AUTHORIZATION_ENDPOINT": "https://explicit/auth",
            "TOKEN_ENDPOINT": "https://explicit/token",
            "END_SESSION_ENDPOINT": "https://explicit/logout",
        }
    ):
        endpoints = oidc.resolve_endpoints(ISSUER, oidc.get_admin_settings())

    assert endpoints == {
        "authorization_endpoint": "https://explicit/auth",
        "token_endpoint": "https://explicit/token",
        "end_session_endpoint": "https://explicit/logout",
    }


def test_resolve_endpoints_falls_back_to_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_discovery(issuer: str, *, timeout: int) -> dict[str, str]:
        assert issuer == ISSUER
        return {
            "authorization_endpoint": f"{issuer}/auth",
            "token_endpoint": f"{issuer}/token",
            "end_session_endpoint": f"{issuer}/logout",
        }

    monkeypatch.setattr(oidc, "get_discovery_document", _fake_discovery)

    endpoints = oidc.resolve_endpoints(ISSUER, oidc.get_admin_settings())

    assert endpoints["authorization_endpoint"] == f"{ISSUER}/auth"
    assert endpoints["token_endpoint"] == f"{ISSUER}/token"
    assert endpoints["end_session_endpoint"] == f"{ISSUER}/logout"


def test_validate_id_token_accepts_valid_token(make_token: TokenFactory) -> None:
    token = _id_token(make_token)
    claims = oidc.validate_id_token(token)
    assert claims["azp"] == ADMIN_CLIENT_ID


def test_validate_id_token_rejects_wrong_typ(make_token: TokenFactory) -> None:
    token = _id_token(make_token, typ="Bearer")
    with pytest.raises(TokenInvalid, match="unexpected_typ"):
        oidc.validate_id_token(token)


def test_validate_id_token_rejects_wrong_audience(make_token: TokenFactory) -> None:
    token = make_token(claims={"aud": "some-other-client", "azp": ADMIN_CLIENT_ID, "typ": "ID"})
    with pytest.raises(TokenInvalid):
        oidc.validate_id_token(token)


def test_validate_id_token_rejects_wrong_azp(make_token: TokenFactory) -> None:
    token = _id_token(make_token, azp="some-other-client")
    with pytest.raises(TokenInvalid, match="azp_not_allowed"):
        oidc.validate_id_token(token)


def test_validate_id_token_rejects_expired(make_token: TokenFactory) -> None:
    now = int(time.time())
    token = _id_token(make_token, iat=now - 1000, exp=now - 100)
    with pytest.raises(TokenExpired):
        oidc.validate_id_token(token)
