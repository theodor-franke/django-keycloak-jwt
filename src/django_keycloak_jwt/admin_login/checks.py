"""Django system checks for ``KEYCLOAK_JWT_ADMIN`` misconfiguration."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.conf import settings
from django.core.checks import CheckMessage, Error, Warning

from ..conf import DEFAULTS as CORE_DEFAULTS
from .conf import DEFAULTS, KNOWN_KEYS, REQUIRED_KEYS


def check_keycloak_jwt_admin_settings(
    *,
    app_configs: Sequence[AppConfig] | None,
    databases: Sequence[str] | None = None,
    **kwargs: Any,
) -> list[CheckMessage]:
    messages: list[CheckMessage] = []
    raw: dict[str, Any] | None = getattr(settings, "KEYCLOAK_JWT_ADMIN", None)

    if raw is None:
        messages.append(
            Error(
                "KEYCLOAK_JWT_ADMIN setting is not configured.",
                hint="Define a KEYCLOAK_JWT_ADMIN dict, or remove "
                "'django_keycloak_jwt.admin_login' from INSTALLED_APPS.",
                id="django_keycloak_jwt.admin_login.E001",
            )
        )
        return messages

    for key in REQUIRED_KEYS:
        if not raw.get(key):
            messages.append(
                Error(
                    f"KEYCLOAK_JWT_ADMIN[{key!r}] is required.",
                    id="django_keycloak_jwt.admin_login.E002",
                )
            )

    unknown = set(raw) - KNOWN_KEYS
    if unknown:
        messages.append(
            Warning(
                f"KEYCLOAK_JWT_ADMIN contains unknown key(s): {sorted(unknown)}.",
                id="django_keycloak_jwt.admin_login.W001",
            )
        )

    core_raw: dict[str, Any] = getattr(settings, "KEYCLOAK_JWT", None) or {}
    user_model_enabled = core_raw.get("USER_MODEL_ENABLED", CORE_DEFAULTS["USER_MODEL_ENABLED"])
    if not user_model_enabled:
        messages.append(
            Error(
                "KEYCLOAK_JWT['USER_MODEL_ENABLED'] must be True to use admin_login.",
                hint="admin_login resolves a real AUTH_USER_MODEL row via the "
                "USER_MODEL_* settings on KEYCLOAK_JWT.",
                id="django_keycloak_jwt.admin_login.E003",
            )
        )

    role_map = core_raw.get("USER_MODEL_ROLE_FIELD_MAP", CORE_DEFAULTS["USER_MODEL_ROLE_FIELD_MAP"])
    if not role_map:
        messages.append(
            Error(
                "KEYCLOAK_JWT['USER_MODEL_ROLE_FIELD_MAP'] must not be empty when "
                "admin_login is installed.",
                hint="Without it, any authenticated Keycloak user would be granted "
                "an admin session with no is_staff/is_superuser flag ever set, "
                "and the role gate in the callback view would reject everyone.",
                id="django_keycloak_jwt.admin_login.E004",
            )
        )

    if raw.get("AUTHORIZATION_ENDPOINT") is not None:
        endpoint = raw["AUTHORIZATION_ENDPOINT"]
    else:
        endpoint = DEFAULTS["AUTHORIZATION_ENDPOINT"]
    if endpoint and not settings.DEBUG and not str(endpoint).startswith("https://"):
        messages.append(
            Warning(
                f"KEYCLOAK_JWT_ADMIN['AUTHORIZATION_ENDPOINT'] ({endpoint!r}) is not "
                "HTTPS while DEBUG=False.",
                id="django_keycloak_jwt.admin_login.W002",
            )
        )

    cookie_mode = raw.get("COOKIE_MODE", DEFAULTS["COOKIE_MODE"])
    access_cookie_secure = raw.get("ACCESS_COOKIE_SECURE", DEFAULTS["ACCESS_COOKIE_SECURE"])
    if cookie_mode and not access_cookie_secure and not settings.DEBUG:
        messages.append(
            Warning(
                "KEYCLOAK_JWT_ADMIN['ACCESS_COOKIE_SECURE'] is False while DEBUG=False -- "
                "the admin access-token cookie will be sent over plain HTTP.",
                id="django_keycloak_jwt.admin_login.W003",
            )
        )

    return messages
