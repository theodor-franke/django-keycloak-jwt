from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth.models import AnonymousUser, User
from django.contrib.sessions.backends.cache import SessionStore
from django.test import RequestFactory, override_settings

from django_keycloak_jwt.admin_login import oidc, views
from django_keycloak_jwt.admin_login.conf import get_admin_settings

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


def _request(path: str = "/admin-login/callback/", **get_params: str):
    request = factory.get(path, get_params)
    request.session = SessionStore()
    request.user = AnonymousUser()  # normally set by AuthenticationMiddleware
    return request


def _id_token(make_token: TokenFactory, **overrides: Any) -> str:
    claims = {
        "aud": ADMIN_CLIENT_ID,
        "azp": ADMIN_CLIENT_ID,
        "typ": "ID",
        "sub": "alice-sub",
        **overrides,
    }
    return make_token(claims=claims)


def test_login_redirects_with_state_and_pkce_challenge() -> None:
    request = _request("/admin-login/login/", next="/admin/notes/")
    response = views.login(request)

    assert response.status_code == 302
    parsed = urlparse(response.url)
    query = parse_qs(parsed.query)
    assert query["client_id"] == [ADMIN_CLIENT_ID]
    assert query["code_challenge_method"] == ["S256"]
    assert "state" in query and "code_challenge" in query
    assert request.session[views.SESSION_STATE_KEY] == query["state"][0]
    assert request.session[views.SESSION_NEXT_KEY] == "/admin/notes/"


def test_callback_rejects_error_param() -> None:
    request = _request(error="access_denied")
    response = views.callback(request)
    assert response.status_code == 400


def test_callback_rejects_state_mismatch() -> None:
    request = _request(state="wrong", code="abc")
    request.session[views.SESSION_STATE_KEY] = "expected"
    request.session[views.SESSION_VERIFIER_KEY] = "verifier"
    response = views.callback(request)
    assert response.status_code == 400


def test_callback_rejects_missing_code() -> None:
    request = _request(state="expected")
    request.session[views.SESSION_STATE_KEY] = "expected"
    request.session[views.SESSION_VERIFIER_KEY] = "verifier"
    response = views.callback(request)
    assert response.status_code == 400


@pytest.mark.django_db
def test_callback_success_logs_in_and_redirects(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = _id_token(make_token, resource_access={"api": {"roles": ["admin"]}})
    monkeypatch.setattr(
        oidc,
        "exchange_code",
        lambda **kwargs: {"id_token": token, "refresh_token": "rt", "expires_in": 300},
    )

    request = _request(state="expected", code="abc")
    request.session[views.SESSION_STATE_KEY] = "expected"
    request.session[views.SESSION_VERIFIER_KEY] = "verifier"
    request.session[views.SESSION_NEXT_KEY] = "/admin/next/"

    response = views.callback(request)

    assert response.status_code == 302
    assert response.url == "/admin/next/"
    assert request.user.is_authenticated
    assert request.user.is_superuser is True
    assert request.session[views.SESSION_REFRESH_TOKEN_KEY] == "rt"
    assert User.objects.filter(username="alice-sub").exists()


@pytest.mark.django_db
def test_callback_denies_login_without_required_role(
    monkeypatch: pytest.MonkeyPatch, make_token: TokenFactory
) -> None:
    token = _id_token(make_token, sub="no-roles-sub", resource_access={})
    monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"id_token": token})

    request = _request(state="expected", code="abc")
    request.session[views.SESSION_STATE_KEY] = "expected"
    request.session[views.SESSION_VERIFIER_KEY] = "verifier"

    response = views.callback(request)

    assert response.status_code == 403


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
        token = _id_token(make_token)
        monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"id_token": token})

        request = _request(state="expected", code="abc")
        request.session[views.SESSION_STATE_KEY] = "expected"
        request.session[views.SESSION_VERIFIER_KEY] = "verifier"

        response = views.callback(request)

    assert response.status_code == 403


def test_callback_missing_id_token_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oidc, "exchange_code", lambda **kwargs: {"access_token": "x"})

    request = _request(state="expected", code="abc")
    request.session[views.SESSION_STATE_KEY] = "expected"
    request.session[views.SESSION_VERIFIER_KEY] = "verifier"

    response = views.callback(request)
    assert response.status_code == 400


def test_logout_ends_session_and_redirects_to_keycloak() -> None:
    request = _request("/admin-login/logout/")
    request.session[views.SESSION_ID_TOKEN_KEY] = "the-id-token"

    response = views.logout(request)

    assert response.status_code == 302
    assert response.url.startswith(get_admin_settings().END_SESSION_ENDPOINT)
    assert "id_token_hint=the-id-token" in response.url


def test_logout_without_end_session_redirects_to_admin() -> None:
    with override_settings(
        KEYCLOAK_JWT=CORE_SETTINGS,
        KEYCLOAK_JWT_ADMIN={**ADMIN_SETTINGS, "LOGOUT_END_SESSION": False},
    ):
        request = _request("/admin-login/logout/")
        response = views.logout(request)

    assert response.status_code == 302
    assert response.url == get_admin_settings().LOGIN_REDIRECT_URL
