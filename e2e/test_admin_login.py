"""e2e coverage for the admin_login module's Keycloak-facing pieces.

Driving the *browser* half of the Authorization Code + PKCE redirect (a
real login form submission at Keycloak) would need a headless browser,
which this repo doesn't otherwise depend on. Instead these tests exercise
every piece that actually talks to Keycloak -- discovery, ID-token
validation against real signing keys, and the refresh grant -- using the
"django-admin" test client's directAccessGrantsEnabled (test-realm-only,
same trick "frontend" already uses for the API e2e tests) to obtain real
tokens without a browser. The view-level HTTP flow (state/PKCE handling,
role gate, session creation) is covered by unit tests with these calls
mocked at the ``oidc`` module boundary.
"""

from __future__ import annotations

import pytest
import requests

from django_keycloak_jwt.admin_login import oidc
from django_keycloak_jwt.admin_login.conf import get_admin_settings
from django_keycloak_jwt.conf import get_settings
from django_keycloak_jwt.user_resolution import resolve_user

from .conftest import TOKEN_URL

pytestmark = [pytest.mark.e2e, pytest.mark.django_db(transaction=True)]


def _admin_tokens(username: str, password: str) -> dict[str, str]:
    data = {
        "grant_type": "password",
        "client_id": get_admin_settings().CLIENT_ID,
        "username": username,
        "password": password,
        "scope": "openid",
    }
    response = requests.post(TOKEN_URL, data=data, timeout=10)
    response.raise_for_status()
    result: dict[str, str] = response.json()
    return result


def test_resolve_endpoints_discovers_real_keycloak() -> None:
    issuer = get_settings().ISSUER
    endpoints = oidc.resolve_endpoints(issuer, get_admin_settings())

    assert endpoints["authorization_endpoint"].startswith(issuer)
    assert endpoints["token_endpoint"].startswith(issuer)
    assert endpoints["end_session_endpoint"].startswith(issuer)


def test_validate_id_token_accepts_real_keycloak_token() -> None:
    tokens = _admin_tokens("alice", "alice-pass")

    claims = oidc.validate_id_token(tokens["id_token"])

    assert claims["preferred_username"] == "alice"
    assert claims["azp"] == get_admin_settings().CLIENT_ID
    assert claims["typ"] == "ID"


def test_validate_id_token_rejects_access_token_as_id_token() -> None:
    tokens = _admin_tokens("alice", "alice-pass")

    with pytest.raises(Exception, match="unexpected_typ"):
        oidc.validate_id_token(tokens["access_token"])


def test_resolve_user_grants_admin_roles_for_alice() -> None:
    tokens = _admin_tokens("alice", "alice-pass")
    claims = oidc.validate_id_token(tokens["id_token"])

    user = resolve_user(claims)

    assert user.is_staff is True
    assert user.is_superuser is True


def test_resolve_user_denies_admin_roles_for_bob() -> None:
    tokens = _admin_tokens("bob", "bob-pass")
    claims = oidc.validate_id_token(tokens["id_token"])

    user = resolve_user(claims)

    assert user.is_staff is False
    assert user.is_superuser is False


def test_refresh_tokens_returns_a_revalidatable_id_token() -> None:
    tokens = _admin_tokens("alice", "alice-pass")
    endpoints = oidc.resolve_endpoints(get_settings().ISSUER, get_admin_settings())

    refreshed = oidc.refresh_tokens(
        endpoints=endpoints,
        client_id=get_admin_settings().CLIENT_ID,
        refresh_token=tokens["refresh_token"],
        timeout=5,
    )

    claims = oidc.validate_id_token(refreshed["id_token"])
    assert claims["preferred_username"] == "alice"
