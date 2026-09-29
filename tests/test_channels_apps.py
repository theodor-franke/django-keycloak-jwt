from __future__ import annotations

from django.apps import AppConfig

from django_keycloak_jwt.channels.apps import KeycloakJWTChannelsConfig


def test_app_config_ready_registers_check() -> None:
    config = AppConfig.create("django_keycloak_jwt.channels")
    assert isinstance(config, KeycloakJWTChannelsConfig)
    config.ready()
