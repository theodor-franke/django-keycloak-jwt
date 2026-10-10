"""e2e coverage for admin_login's COOKIE_MODE against real Keycloak + Postgres.

Uses the **``frontend``** client (the SPA's own client, `directAccessGrantsEnabled`
for test-realm-only password-grant access, see ``realm-test.json``) instead of the
dedicated ``django-admin`` client that the session-mode e2e tests
(``test_admin_login.py``) use -- that's the entire point of cookie mode being
provable here: Django admin authenticating through the same client the frontend
already does.

Driving the real Authorization Code + PKCE redirect through Keycloak's actual
login *form* would need a headless browser, which this repo doesn't otherwise
depend on (see ``test_admin_login.py``'s module docstring for the established
split). Instead: ``login`` is driven for real over HTTP against the real live
server (proving discovery + state-cookie issuance work against the real
realm), and ``oidc.exchange_code`` is mocked to return tokens obtained via a
*real* call to Keycloak's actual token endpoint -- just via the password grant
(``frontend``'s `directAccessGrantsEnabled`) rather than an authorization code,
since minting a real code needs that same browser leg. Every other step --
state-cookie verification, ``validate_token``, ``resolve_user`` against the
real Postgres DB, cookie issuance, and the subsequent request's
``KeycloakAdminCookieMiddleware`` re-validation -- runs for real over real
HTTP against the live server.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from django.test import override_settings

from django_keycloak_jwt.admin_login import oidc
from django_keycloak_jwt.admin_login.conf import get_admin_settings

from .conftest import TokenGetter

pytestmark = [pytest.mark.e2e, pytest.mark.django_db(transaction=True)]

COOKIE_MODE_ADMIN_SETTINGS: dict[str, Any] = {
    "CLIENT_ID": "frontend",
    "COOKIE_MODE": True,
}


def _login_get_state_and_cookie(live_server: Any) -> tuple[str, str]:
    """Drive the real ``login`` view and return ``(state, state_cookie_value)``.

    Proves discovery + signed state-cookie issuance against the real realm --
    the only thing not driven for real here is the browser submitting
    Keycloak's login form (see module docstring).
    """
    response = requests.get(
        f"{live_server.url}/admin-login/login/",
        params={"next": "/admin/"},
        allow_redirects=False,
        timeout=10,
    )
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["Location"]).query)
    state = query["state"][0]
    state_cookie_name = get_admin_settings().STATE_COOKIE_NAME
    return state, response.cookies[state_cookie_name]


def _callback(live_server: Any, *, state: str, state_cookie_value: str) -> requests.Response:
    return requests.get(
        f"{live_server.url}/admin-login/callback/",
        params={"state": state, "code": "irrelevant-mocked-exchange"},
        cookies={get_admin_settings().STATE_COOKIE_NAME: state_cookie_value},
        allow_redirects=False,
        timeout=10,
    )


def test_token_size_fits_the_cookie_budget(alice_token: str) -> None:
    """Empirical check from KEYCLOAK_JWT_ADMIN_COOKIE_SPEC.md Sec 1: the
    real encoded access token (frontend client, alice's actual realm +
    client roles) must comfortably fit a single cookie. Measured at
    ~1283 bytes (~1375 bytes as a full Set-Cookie line) when this test was
    written -- re-run if the realm's role/claim set grows significantly.
    """
    encoded_length = len(alice_token.encode())
    assert encoded_length < 3000, (
        f"access token is {encoded_length} bytes encoded -- too close to browser "
        "cookie/header-size limits for COOKIE_MODE; see spec Sec 1."
    )


def test_alice_cookie_login_resolves_admin_user_on_subsequent_request(
    monkeypatch: pytest.MonkeyPatch,
    live_server: Any,
    get_token: TokenGetter,
) -> None:
    access_token = get_token("frontend", "alice", "alice-pass")
    monkeypatch.setattr(
        oidc, "exchange_code", lambda **kwargs: {"access_token": access_token, "expires_in": 300}
    )

    with override_settings(KEYCLOAK_JWT_ADMIN=COOKIE_MODE_ADMIN_SETTINGS):
        state, state_cookie_value = _login_get_state_and_cookie(live_server)
        response = _callback(live_server, state=state, state_cookie_value=state_cookie_value)

        assert response.status_code == 302
        assert response.headers["Location"] == "/admin/"
        access_cookie_name = get_admin_settings().ACCESS_COOKIE_NAME
        access_cookie_value = response.cookies[access_cookie_name]
        assert access_cookie_value == access_token

        admin_response = requests.get(
            f"{live_server.url}/admin/",
            cookies={access_cookie_name: access_cookie_value},
            allow_redirects=False,
            timeout=10,
        )
        assert admin_response.status_code == 200
        assert b"Site administration" in admin_response.content


def test_bob_cookie_login_denied_without_admin_role(
    monkeypatch: pytest.MonkeyPatch,
    live_server: Any,
    get_token: TokenGetter,
) -> None:
    access_token = get_token("frontend", "bob", "bob-pass")
    monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"access_token": access_token})

    with override_settings(KEYCLOAK_JWT_ADMIN=COOKIE_MODE_ADMIN_SETTINGS):
        state, state_cookie_value = _login_get_state_and_cookie(live_server)
        response = _callback(live_server, state=state, state_cookie_value=state_cookie_value)

    assert response.status_code == 403
    assert get_admin_settings().ACCESS_COOKIE_NAME not in response.cookies


def test_expired_real_token_cookie_leaves_request_anonymous(
    live_server: Any, get_token: TokenGetter
) -> None:
    # frontend-short has a 5s access-token lifespan (same trick test_api.py's
    # test_frontend_short_expires uses) -- no need for a real login dance
    # here, just a real-but-expired token presented straight to the
    # already-cookie-mode-enabled admin surface.
    expired_token = get_token("frontend-short", "alice", "alice-pass")
    time.sleep(6)

    with override_settings(KEYCLOAK_JWT_ADMIN=COOKIE_MODE_ADMIN_SETTINGS):
        access_cookie_name = get_admin_settings().ACCESS_COOKIE_NAME
        response = requests.get(
            f"{live_server.url}/admin/",
            cookies={access_cookie_name: expired_token},
            allow_redirects=False,
            timeout=10,
        )

    # AuthenticationMiddleware leaves request.user anonymous; admin's own
    # has_permission check then redirects to admin:login (which itself
    # redirects into keycloak_admin_login:login), same as a first-time
    # visitor -- exactly like the missing-cookie case, just one hop further.
    assert response.status_code == 302
    assert "/admin/login/" in response.headers["Location"]
