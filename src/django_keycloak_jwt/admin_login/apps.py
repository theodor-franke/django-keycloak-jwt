from __future__ import annotations

from django.apps import AppConfig
from django.core.checks import register

from .checks import check_keycloak_jwt_admin_settings


class KeycloakJWTAdminLoginConfig(AppConfig):
    name = "django_keycloak_jwt.admin_login"
    label = "django_keycloak_jwt_admin_login"
    verbose_name = "Keycloak JWT Admin Login"

    def ready(self) -> None:
        register(check_keycloak_jwt_admin_settings)
