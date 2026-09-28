from __future__ import annotations

from django.apps import AppConfig

from django_keycloak_jwt.admin_login.apps import KeycloakJWTAdminLoginConfig
from django_keycloak_jwt.admin_login.backends import KeycloakAdminBackend


def test_backend_authenticate_always_returns_none() -> None:
    assert KeycloakAdminBackend().authenticate(None) is None
    assert KeycloakAdminBackend().authenticate(None, extra="ignored") is None


def test_app_config_ready_registers_check() -> None:
    config = AppConfig.create("django_keycloak_jwt.admin_login")
    assert isinstance(config, KeycloakJWTAdminLoginConfig)
    config.ready()
