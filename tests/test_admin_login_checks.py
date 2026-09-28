from __future__ import annotations

from django.core.checks import Error, Warning
from django.test import override_settings

from django_keycloak_jwt.admin_login.checks import check_keycloak_jwt_admin_settings

VALID_CORE = {
    "ISSUER": "https://kc.example.test/realms/test",
    "AUDIENCE": "x",
    "USER_MODEL_ENABLED": True,
    "USER_MODEL_LOOKUP_FIELD": "keycloak_sub",
    "USER_MODEL_ROLE_FIELD_MAP": {"admin": "is_superuser"},
}


def test_missing_setting_is_error() -> None:
    with override_settings(KEYCLOAK_JWT_ADMIN=None, KEYCLOAK_JWT=VALID_CORE):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert any(m.id == "django_keycloak_jwt.admin_login.E001" for m in messages)


def test_missing_client_id_is_error() -> None:
    with override_settings(KEYCLOAK_JWT_ADMIN={}, KEYCLOAK_JWT=VALID_CORE):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.admin_login.E002" and isinstance(m, Error) for m in messages
    )


def test_unknown_key_is_warning() -> None:
    with override_settings(
        KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "django-admin", "TYPO": "x"},
        KEYCLOAK_JWT=VALID_CORE,
    ):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.admin_login.W001" and isinstance(m, Warning) for m in messages
    )


def test_user_model_disabled_is_error() -> None:
    with override_settings(
        KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "django-admin"},
        KEYCLOAK_JWT={"ISSUER": "https://kc.example.test/realms/test", "AUDIENCE": "x"},
    ):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert any(m.id == "django_keycloak_jwt.admin_login.E003" for m in messages)


def test_empty_role_field_map_is_error() -> None:
    core = {**VALID_CORE, "USER_MODEL_ROLE_FIELD_MAP": {}}
    with override_settings(KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "django-admin"}, KEYCLOAK_JWT=core):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert any(m.id == "django_keycloak_jwt.admin_login.E004" for m in messages)


def test_non_https_authorization_endpoint_with_debug_false_is_warning() -> None:
    with override_settings(
        DEBUG=False,
        KEYCLOAK_JWT_ADMIN={
            "CLIENT_ID": "django-admin",
            "AUTHORIZATION_ENDPOINT": "http://kc.example.test/auth",
        },
        KEYCLOAK_JWT=VALID_CORE,
    ):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert any(
        m.id == "django_keycloak_jwt.admin_login.W002" and isinstance(m, Warning) for m in messages
    )


def test_valid_settings_produce_no_messages() -> None:
    with override_settings(
        DEBUG=True, KEYCLOAK_JWT_ADMIN={"CLIENT_ID": "django-admin"}, KEYCLOAK_JWT=VALID_CORE
    ):
        messages = check_keycloak_jwt_admin_settings(app_configs=None)
    assert messages == []
