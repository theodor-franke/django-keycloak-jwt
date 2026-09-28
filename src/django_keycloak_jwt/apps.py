from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.apps import AppConfig
from django.contrib.auth import get_user_model
from django.core.checks import register
from django.core.exceptions import ImproperlyConfigured
from django.db.models.signals import post_delete, post_save

from .checks import check_keycloak_jwt_settings
from .conf import get_settings
from .user_resolution import invalidate_user_cache

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser


class KeycloakJWTConfig(AppConfig):
    name = "django_keycloak_jwt"
    verbose_name = "Keycloak JWT"

    def ready(self) -> None:
        register(check_keycloak_jwt_settings)

        try:
            user_model_enabled = get_settings().USER_MODEL_ENABLED
        except ImproperlyConfigured:
            # Misconfiguration is reported by the system check above, not a
            # startup crash -- e.g. `manage.py check` needs to run at all.
            user_model_enabled = False

        if not user_model_enabled:
            return

        user_model = get_user_model()
        post_save.connect(
            _on_user_saved,
            sender=user_model,
            dispatch_uid="django_keycloak_jwt_user_saved",
        )
        post_delete.connect(
            _on_user_deleted,
            sender=user_model,
            dispatch_uid="django_keycloak_jwt_user_deleted",
        )


def _on_user_saved(*, instance: AbstractBaseUser, **kwargs: Any) -> None:
    invalidate_user_cache(instance)


def _on_user_deleted(*, instance: AbstractBaseUser, **kwargs: Any) -> None:
    invalidate_user_cache(instance)
