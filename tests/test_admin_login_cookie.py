"""COOKIE_MODE coverage for admin_login: views.login/callback/logout's
cookie-based branch and KeycloakAdminCookieMiddleware.

Mirrors tests/test_admin_login_views.py's and test_admin_login_middleware.py's
conventions (same settings shape, same mocking-at-the-``oidc``-module-boundary
style) -- session-mode behavior is covered there and deliberately untouched
by this file.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth.models import AnonymousUser, User
from django.contrib.sessions.backends.cache import SessionStore
from django.core import signing
from django.test import RequestFactory, override_settings

from django_keycloak_jwt import user_resolution
from django_keycloak_jwt.admin_login import oidc, views
from django_keycloak_jwt.admin_login.conf import get_admin_settings
from django_keycloak_jwt.admin_login.cookie_middleware import KeycloakAdminCookieMiddleware

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory

factory = RequestFactory()

ADMIN_CLIENT_ID = "frontend"

CORE_SETTINGS: dict[str, Any] = {
    "ISSUER": ISSUER,
    "AUDIENCE": AUDIENCE,
    "ROLE_CLIENT": "api",
    "USER_MODEL_ENABLED": True,
    "USER_MODEL_LOOKUP_CLAIM": "sub",
    "USER_MODEL_LOOKUP_FIELD": "username",
    "USER_MODEL_FIELD_MAP": {"email": "email"},
    "USER_MODEL_ROLE_FIELD_MAP": {"admin": "is_superuser"},
}

ADMIN_SETTINGS: dict[str, Any] = {
    "CLIENT_ID": ADMIN_CLIENT_ID,
    "AUTHORIZATION_ENDPOINT": "https://kc.example.test/auth",
    "TOKEN_ENDPOINT": "https://kc.example.test/token",
    "END_SESSION_ENDPOINT": "https://kc.example.test/logout",
    "COOKIE_MODE": True,
}


@pytest.fixture(autouse=True)
def _settings(jwks_server: JWKSServer, signer: Signer):
    with override_settings(
        KEYCLOAK_JWT={**CORE_SETTINGS, "JWKS_URL": jwks_server.url},
        KEYCLOAK_JWT_ADMIN=ADMIN_SETTINGS,
        ROOT_URLCONF="tests.admin_login_urls",
    ):
        jwks_server.set_keys(signer.jwk)
        yield


def _request(path: str = "/admin-login/callback/", **get_params: str) -> Any:
    request = factory.get(path, get_params)
    request.session = SessionStore()
    request.user = AnonymousUser()  # normally set by AuthenticationMiddleware
    return request


def _access_token(make_token: TokenFactory, **overrides: Any) -> str:
    # Deliberately relies on make_token()'s defaults (aud=AUDIENCE, typ="Bearer")
    # -- exactly the access-token shape the frontend already sends as
    # `Authorization: Bearer <token>`, which is the whole point of cookie mode.
    claims = {"sub": "alice-sub", **overrides}
    return make_token(claims=claims)


def _state_cookie(
    *, state: str = "expected", verifier: str = "verifier", next_url: str = "/admin/next/"
) -> str:
    return signing.dumps(
        {"state": state, "verifier": verifier, "next": next_url}, salt=views.STATE_COOKIE_SALT
    )


def _set_state_cookie(request: Any, value: str) -> None:
    request.COOKIES[get_admin_settings().STATE_COOKIE_NAME] = value


# -- login -------------------------------------------------------------


def test_login_sets_signed_state_cookie_not_session() -> None:
    request = _request("/admin-login/login/", next="/admin/notes/")
    response = views.login(request)

    assert response.status_code == 302
    admin_settings = get_admin_settings()
    cookie = response.cookies[admin_settings.STATE_COOKIE_NAME]
    assert cookie["httponly"] is True
    assert cookie["secure"] is True
    assert cookie["samesite"] == "Lax"
    assert cookie["max-age"] == admin_settings.STATE_COOKIE_MAX_AGE

    payload = signing.loads(cookie.value, salt=views.STATE_COOKIE_SALT)
    parsed = urlparse(response.url)
    query = parse_qs(parsed.query)
    assert payload["state"] == query["state"][0]
    assert payload["next"] == "/admin/notes/"

    assert views.SESSION_STATE_KEY not in request.session
    assert views.SESSION_VERIFIER_KEY not in request.session
    assert views.SESSION_NEXT_KEY not in request.session
    assert len(request.session.keys()) == 0


# -- callback: state-cookie handling -------------------------------------


def test_callback_missing_state_cookie_is_400() -> None:
    request = _request(state="expected", code="abc")
    response = views.callback(request)
    assert response.status_code == 400


def test_callback_tampered_state_cookie_is_400() -> None:
    request = _request(state="expected", code="abc")
    _set_state_cookie(request, _state_cookie() + "tampered")
    response = views.callback(request)
    assert response.status_code == 400


def test_callback_expired_state_cookie_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    real_time = time.time
    monkeypatch.setattr(signing.time, "time", lambda: real_time() - 10_000)
    cookie_value = _state_cookie()
    monkeypatch.setattr(signing.time, "time", real_time)

    request = _request(state="expected", code="abc")
    _set_state_cookie(request, cookie_value)

    response = views.callback(request)
    assert response.status_code == 400


def test_callback_rejects_state_mismatch() -> None:
    request = _request(state="wrong", code="abc")
    _set_state_cookie(request, _state_cookie(state="expected"))
    response = views.callback(request)
    assert response.status_code == 400


# -- callback: success / role gate / token-validator used ----------------


@pytest.mark.django_db
def test_callback_success_sets_access_cookie_and_skips_django_login(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = _access_token(make_token, resource_access={"api": {"roles": ["admin"]}})
    monkeypatch.setattr(
        oidc, "exchange_code", lambda **kwargs: {"access_token": token, "expires_in": 300}
    )
    login_calls: list[Any] = []
    monkeypatch.setattr(views, "django_login", lambda *a, **k: login_calls.append((a, k)))

    request = _request(state="expected", code="abc")
    _set_state_cookie(request, _state_cookie(state="expected", next_url="/admin/next/"))

    response = views.callback(request)

    assert response.status_code == 302
    assert response.url == "/admin/next/"
    assert login_calls == []
    assert User.objects.filter(username="alice-sub", is_superuser=True).exists()

    admin_settings = get_admin_settings()
    state_cookie = response.cookies[admin_settings.STATE_COOKIE_NAME]
    assert state_cookie.value == "" and state_cookie["max-age"] == 0  # deleted

    access_cookie = response.cookies[admin_settings.ACCESS_COOKIE_NAME]
    assert access_cookie.value == token
    assert access_cookie["httponly"] is True
    assert access_cookie["secure"] is True
    assert access_cookie["samesite"] == "Lax"
    assert access_cookie["path"] == admin_settings.ACCESS_COOKIE_PATH
    # max_age is derived from the token's own exp, not a fixed/longer value.
    assert 0 < access_cookie["max-age"] <= 300


@pytest.mark.django_db
def test_callback_denies_login_without_required_role(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = _access_token(make_token, resource_access={})
    monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"access_token": token})

    request = _request(state="expected", code="abc")
    _set_state_cookie(request, _state_cookie())

    response = views.callback(request)

    assert response.status_code == 403


@pytest.mark.django_db
def test_callback_uses_validate_token_not_validate_id_token(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = _access_token(make_token, resource_access={"api": {"roles": ["admin"]}})
    monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"access_token": token})

    validate_token_calls: list[str] = []
    real_validate_token = views.validate_token

    def _spy_validate_token(raw: str):
        validate_token_calls.append(raw)
        return real_validate_token(raw)

    monkeypatch.setattr(views, "validate_token", _spy_validate_token)

    validate_id_token_calls: list[str] = []

    def _spy_validate_id_token(raw: str) -> None:
        validate_id_token_calls.append(raw)

    monkeypatch.setattr(oidc, "validate_id_token", _spy_validate_id_token)

    request = _request(state="expected", code="abc")
    _set_state_cookie(request, _state_cookie())

    response = views.callback(request)

    assert response.status_code == 302
    assert validate_token_calls == [token]
    assert validate_id_token_calls == []


def test_callback_missing_access_token_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"id_token": "x"})

    request = _request(state="expected", code="abc")
    _set_state_cookie(request, _state_cookie())

    response = views.callback(request)
    assert response.status_code == 400


def test_callback_invalid_access_token_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oidc, "exchange_code", lambda **kwargs: {"access_token": "not-a-real-token"}
    )

    request = _request(state="expected", code="abc")
    _set_state_cookie(request, _state_cookie())

    response = views.callback(request)
    assert response.status_code == 400


@pytest.mark.django_db
def test_callback_user_not_provisioned_is_403(
    monkeypatch: pytest.MonkeyPatch,
    make_token: TokenFactory,
    jwks_server: JWKSServer,
) -> None:
    with override_settings(
        KEYCLOAK_JWT={
            **CORE_SETTINGS,
            "JWKS_URL": jwks_server.url,
            "USER_MODEL_AUTO_CREATE": False,
        },
        KEYCLOAK_JWT_ADMIN=ADMIN_SETTINGS,
    ):
        token = _access_token(make_token)
        monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"access_token": token})

        request = _request(state="expected", code="abc")
        _set_state_cookie(request, _state_cookie())

        response = views.callback(request)

    assert response.status_code == 403


# -- logout --------------------------------------------------------------


def test_logout_deletes_access_cookie_and_skips_django_logout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logout_calls: list[Any] = []
    monkeypatch.setattr(views, "django_logout", lambda *a, **k: logout_calls.append((a, k)))

    request = _request("/admin-login/logout/")
    response = views.logout(request)

    assert response.status_code == 302
    assert logout_calls == []
    admin_settings = get_admin_settings()
    assert response.url.startswith(admin_settings.END_SESSION_ENDPOINT)
    cookie = response.cookies[admin_settings.ACCESS_COOKIE_NAME]
    assert cookie.value == "" and cookie["max-age"] == 0


def test_logout_without_end_session_still_deletes_cookie() -> None:
    with override_settings(
        KEYCLOAK_JWT=CORE_SETTINGS,
        KEYCLOAK_JWT_ADMIN={**ADMIN_SETTINGS, "LOGOUT_END_SESSION": False},
    ):
        request = _request("/admin-login/logout/")
        response = views.logout(request)

    assert response.status_code == 302
    admin_settings = get_admin_settings()
    assert response.url == admin_settings.LOGIN_REDIRECT_URL
    cookie = response.cookies[admin_settings.ACCESS_COOKIE_NAME]
    assert cookie.value == "" and cookie["max-age"] == 0


# -- KeycloakAdminCookieMiddleware ----------------------------------------


def _middleware() -> tuple[KeycloakAdminCookieMiddleware, list[str]]:
    calls: list[str] = []

    def get_response(request: Any) -> str:
        calls.append("called")
        return "response"

    return KeycloakAdminCookieMiddleware(get_response), calls


def test_middleware_no_cookie_is_noop() -> None:
    middleware, calls = _middleware()
    request = factory.get("/admin/")
    request.user = AnonymousUser()

    result = middleware(request)

    assert result == "response"
    assert calls == ["called"]
    assert request.user.is_anonymous


@pytest.mark.django_db
def test_middleware_valid_cookie_resolves_user_via_resolve_user(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = _access_token(make_token, resource_access={"api": {"roles": ["admin"]}})

    resolve_calls: list[dict[str, Any]] = []
    real_resolve_user = user_resolution.resolve_user

    def _spy_resolve_user(claims: dict[str, Any]):
        resolve_calls.append(claims)
        return real_resolve_user(claims)

    monkeypatch.setattr(
        "django_keycloak_jwt.admin_login.cookie_middleware.resolve_user", _spy_resolve_user
    )

    middleware, _ = _middleware()
    request = factory.get("/admin/")
    request.user = AnonymousUser()
    request.COOKIES[get_admin_settings().ACCESS_COOKIE_NAME] = token

    middleware(request)

    assert request.user.username == "alice-sub"
    assert request.user.is_superuser is True
    assert len(resolve_calls) == 1


def test_middleware_invalid_token_leaves_user_anonymous() -> None:
    middleware, _ = _middleware()
    request = factory.get("/admin/")
    request.user = AnonymousUser()
    request.COOKIES[get_admin_settings().ACCESS_COOKIE_NAME] = "not-a-real-token"

    middleware(request)

    assert request.user.is_anonymous


@pytest.mark.django_db
def test_middleware_expired_token_leaves_user_anonymous(make_token: TokenFactory) -> None:
    expired = _access_token(
        make_token,
        resource_access={"api": {"roles": ["admin"]}},
        iat=int(time.time()) - 1000,
        exp=int(time.time()) - 500,
    )

    middleware, _ = _middleware()
    request = factory.get("/admin/")
    request.user = AnonymousUser()
    request.COOKIES[get_admin_settings().ACCESS_COOKIE_NAME] = expired

    middleware(request)

    assert request.user.is_anonymous


def test_middleware_cookie_mode_disabled_is_noop_even_with_cookie(make_token: TokenFactory) -> None:
    token = _access_token(make_token, resource_access={"api": {"roles": ["admin"]}})

    with override_settings(
        KEYCLOAK_JWT=CORE_SETTINGS,
        KEYCLOAK_JWT_ADMIN={**ADMIN_SETTINGS, "COOKIE_MODE": False},
    ):
        middleware, _ = _middleware()
        request = factory.get("/admin/")
        request.user = AnonymousUser()
        request.COOKIES[get_admin_settings().ACCESS_COOKIE_NAME] = token

        middleware(request)

    assert request.user.is_anonymous


@pytest.mark.django_db
def test_middleware_no_cookie_makes_zero_db_queries(django_assert_num_queries) -> None:
    middleware, _ = _middleware()
    request = factory.get("/admin/")
    request.user = AnonymousUser()

    with django_assert_num_queries(0):
        middleware(request)
