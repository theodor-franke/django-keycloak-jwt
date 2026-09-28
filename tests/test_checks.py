from __future__ import annotations

from django.core.checks import Error, Warning
from django.test import override_settings

from keycloak_jwt.checks import check_keycloak_jwt_settings


def test_missing_setting_is_error() -> None:
    with override_settings(KEYCLOAK_JWT=None):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.E001" for m in messages)


def test_missing_issuer_is_error() -> None:
    with override_settings(KEYCLOAK_JWT={"AUDIENCE": "test-client"}):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.E002" and isinstance(m, Error) for m in messages)


def test_missing_audience_is_error() -> None:
    with override_settings(KEYCLOAK_JWT={"ISSUER": "https://kc.example.test/realms/test"}):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.E002" and isinstance(m, Error) for m in messages)


def test_non_https_issuer_with_debug_false_is_warning() -> None:
    with (
        override_settings(
            DEBUG=False,
            KEYCLOAK_JWT={"ISSUER": "http://kc.example.test/realms/test", "AUDIENCE": "x"},
        ),
    ):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.W001" and isinstance(m, Warning) for m in messages)


def test_non_https_issuer_with_debug_true_is_fine() -> None:
    with override_settings(
        DEBUG=True,
        KEYCLOAK_JWT={"ISSUER": "http://kc.example.test/realms/test", "AUDIENCE": "x"},
    ):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert not any(m.id == "keycloak_jwt.W001" for m in messages)


def test_symmetric_algorithm_is_error() -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "x",
            "ALGORITHMS": ["HS256"],
        }
    ):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.E003" and isinstance(m, Error) for m in messages)


def test_none_algorithm_is_error() -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "x",
            "ALGORITHMS": ["none"],
        }
    ):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.E003" for m in messages)


def test_unknown_key_is_warning() -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "x",
            "TYPO_KEY": "oops",
        }
    ):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert any(m.id == "keycloak_jwt.W002" and isinstance(m, Warning) for m in messages)


def test_valid_settings_produce_no_messages() -> None:
    with override_settings(
        DEBUG=False,
        KEYCLOAK_JWT={"ISSUER": "https://kc.example.test/realms/test", "AUDIENCE": "x"},
    ):
        messages = check_keycloak_jwt_settings(app_configs=None)
    assert messages == []
