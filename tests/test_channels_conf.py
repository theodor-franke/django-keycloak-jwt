from __future__ import annotations

from django.core.checks import Error, Warning
from django.test import override_settings

from django_keycloak_jwt.channels.checks import check_keycloak_jwt_channels_settings
from django_keycloak_jwt.channels.conf import get_channels_settings


def test_defaults_apply_when_setting_absent() -> None:
    # tests/settings.py never defines KEYCLOAK_JWT_CHANNELS at all.
    settings = get_channels_settings()
    assert settings.SUBPROTOCOL_NAME == "access_token"
    assert settings.CLOSE_CODE_TOKEN_INVALID == 4401
    assert settings.CLOSE_CODE_AUTH_UNAVAILABLE == 4503
    assert settings.CLOSE_CODE_TOKEN_EXPIRED == 4001


def test_override_settings_invalidates_cache() -> None:
    with override_settings(KEYCLOAK_JWT_CHANNELS={"SUBPROTOCOL_NAME": "one"}):
        assert get_channels_settings().SUBPROTOCOL_NAME == "one"

    with override_settings(KEYCLOAK_JWT_CHANNELS={"SUBPROTOCOL_NAME": "two"}):
        assert get_channels_settings().SUBPROTOCOL_NAME == "two"

    assert get_channels_settings().SUBPROTOCOL_NAME == "access_token"


def test_valid_settings_produce_no_messages() -> None:
    with override_settings(KEYCLOAK_JWT_CHANNELS=None):
        messages = check_keycloak_jwt_channels_settings(app_configs=None)
    assert messages == []


def test_unknown_key_is_warning() -> None:
    with override_settings(KEYCLOAK_JWT_CHANNELS={"TYPO": "x"}):
        messages = check_keycloak_jwt_channels_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.channels.W001" and isinstance(m, Warning) for m in messages
    )


def test_close_code_out_of_range_is_error() -> None:
    with override_settings(KEYCLOAK_JWT_CHANNELS={"CLOSE_CODE_TOKEN_INVALID": 1000}):
        messages = check_keycloak_jwt_channels_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.channels.E001" and isinstance(m, Error) for m in messages
    )


def test_duplicate_close_codes_is_warning() -> None:
    with override_settings(
        KEYCLOAK_JWT_CHANNELS={"CLOSE_CODE_TOKEN_INVALID": 4001, "CLOSE_CODE_TOKEN_EXPIRED": 4001}
    ):
        messages = check_keycloak_jwt_channels_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.channels.W002" and isinstance(m, Warning) for m in messages
    )


def test_empty_subprotocol_name_is_error() -> None:
    with override_settings(KEYCLOAK_JWT_CHANNELS={"SUBPROTOCOL_NAME": ""}):
        messages = check_keycloak_jwt_channels_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.channels.E002" and isinstance(m, Error) for m in messages
    )
