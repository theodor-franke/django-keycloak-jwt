from __future__ import annotations

from django.apps import AppConfig
from django.core.checks import register

from .checks import check_keycloak_jwt_channels_settings


class KeycloakJWTChannelsConfig(AppConfig):
    name = "django_keycloak_jwt.channels"
    label = "django_keycloak_jwt_channels"
    verbose_name = "Keycloak JWT Channels"

    def ready(self) -> None:
        register(check_keycloak_jwt_channels_settings)
