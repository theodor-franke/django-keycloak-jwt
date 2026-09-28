from __future__ import annotations

import time
from typing import Any

import pytest
from django.contrib.sessions.backends.cache import SessionStore
from django.test import RequestFactory, override_settings

from django_keycloak_jwt.admin_login import oidc, views
from django_keycloak_jwt.admin_login.exceptions import TokenExchangeFailed
from django_keycloak_jwt.admin_login.middleware import KeycloakAdminSessionMiddleware

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory

factory = RequestFactory()

ADMIN_CLIENT_ID = "django-admin"

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
    "REFRESH_LEEWAY": 30,
}


@pytest.fixture(autouse=True)
def _settings(jwks_server: JWKSServer, signer: Signer):
    with override_settings(
        KEYCLOAK_JWT={**CORE_SETTINGS, "JWKS_URL": jwks_server.url},
        KEYCLOAK_JWT_ADMIN=ADMIN_SETTINGS,
    ):
        jwks_server.set_keys(signer.jwk)
        yield


def _middleware() -> tuple[KeycloakAdminSessionMiddleware, list[str]]:
    calls: list[str] = []

    def get_response(request):
        calls.append("called")
        return "response"

    return KeycloakAdminSessionMiddleware(get_response), calls


def _request_with_session() -> Any:
    request = factory.get("/admin/")
    request.session = SessionStore()
    return request


def test_no_session_is_noop() -> None:
    middleware, calls = _middleware()
    request = factory.get("/admin/")
    assert not hasattr(request, "session")

    result = middleware(request)

    assert result == "response"
    assert calls == ["called"]


def test_no_refresh_state_is_noop() -> None:
    middleware, _ = _middleware()
    request = _request_with_session()

    middleware(request)

    assert views.SESSION_REFRESH_TOKEN_KEY not in request.session


def test_not_yet_expiring_is_noop() -> None:
    middleware, _ = _middleware()
    request = _request_with_session()
    request.session[views.SESSION_REFRESH_TOKEN_KEY] = "rt"
    request.session[views.SESSION_TOKEN_EXP_KEY] = time.time() + 1000

    middleware(request)

    assert request.session[views.SESSION_REFRESH_TOKEN_KEY] == "rt"


@pytest.mark.django_db
def test_refresh_success_updates_session_and_user(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = make_token(
        claims={
            "aud": ADMIN_CLIENT_ID,
            "azp": ADMIN_CLIENT_ID,
            "typ": "ID",
            "sub": "alice-sub",
            "resource_access": {"api": {"roles": ["admin"]}},
        }
    )
    monkeypatch.setattr(
        oidc,
        "refresh_tokens",
        lambda **kwargs: {"id_token": token, "refresh_token": "new-rt", "expires_in": 300},
    )

    middleware, _ = _middleware()
    request = _request_with_session()
    request.session[views.SESSION_REFRESH_TOKEN_KEY] = "old-rt"
    request.session[views.SESSION_TOKEN_EXP_KEY] = time.time() - 1

    middleware(request)

    assert request.session[views.SESSION_REFRESH_TOKEN_KEY] == "new-rt"
    assert request.user.username == "alice-sub"
    assert request.user.is_superuser is True


def test_refresh_failure_logs_out(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(**kwargs: Any) -> None:
        raise TokenExchangeFailed("boom")

    monkeypatch.setattr(oidc, "refresh_tokens", _raise)

    middleware, _ = _middleware()
    request = _request_with_session()
    request.session[views.SESSION_REFRESH_TOKEN_KEY] = "old-rt"
    request.session[views.SESSION_TOKEN_EXP_KEY] = time.time() - 1

    middleware(request)

    # django.contrib.auth.logout() flushes the session.
    assert views.SESSION_REFRESH_TOKEN_KEY not in request.session
