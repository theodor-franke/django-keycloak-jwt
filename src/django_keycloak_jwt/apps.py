from __future__ import annotations

from django.apps import AppConfig
from django.core.checks import register

from .checks import check_keycloak_jwt_settings


class KeycloakJWTConfig(AppConfig):
    name = "django_keycloak_jwt"
    verbose_name = "Keycloak JWT"

    def ready(self) -> None:
        register(check_keycloak_jwt_settings)
