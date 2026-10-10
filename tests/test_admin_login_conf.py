from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from django_keycloak_jwt.admin_login.conf import get_admin_settings


def test_missing_setting_entirely_raises() -> None:
    with (
        override_settings(KEYCLOAK_JWT_ADMIN=None),
        pytest.raises(ImproperlyConfigured, match="KEYCLOAK_JWT_ADMIN"),
    ):
        get_admin_settings()


def test_missing_client_id_raises() -> None:
    with (
        override_settings(KEYCLOAK_JWT_ADMIN={}),
        pytest.raises(ImproperlyConfigured, match="CLIENT_ID"),
    ):
        get_admin_settings()


def test_defaults() -> None:
    with override_settings(KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "django-admin"}):
        settings = get_admin_settings()

    assert settings.CLIENT_ID == "django-admin"
    assert settings.AUTHORIZATION_ENDPOINT is None
    assert settings.LOGOUT_END_SESSION is True
    assert settings.SCOPE == "openid"
    assert settings.HTTP_TIMEOUT == 5
    assert settings.LOGIN_REDIRECT_URL == "/admin/"
    assert settings.REFRESH_LEEWAY == 30
    assert settings.COOKIE_MODE is False
    assert settings.ACCESS_COOKIE_NAME == "kc_admin_access_token"
    assert settings.ACCESS_COOKIE_PATH == "/"
    assert settings.ACCESS_COOKIE_SECURE is True
    assert settings.ACCESS_COOKIE_SAMESITE == "Lax"
    assert settings.STATE_COOKIE_NAME == "kc_admin_login_state"
    assert settings.STATE_COOKIE_MAX_AGE == 300


def test_override_settings_invalidates_cache() -> None:
    with override_settings(KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "one"}):
        assert get_admin_settings().CLIENT_ID == "one"

    with override_settings(KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "two"}):
        assert get_admin_settings().CLIENT_ID == "two"
