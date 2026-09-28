"""Django system checks for ``KEYCLOAK_JWT`` misconfiguration."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.conf import settings
from django.core.cache import caches
from django.core.checks import CheckMessage, Error, Warning

from .conf import DEFAULTS, FORBIDDEN_ALGORITHMS, KNOWN_KEYS, REQUIRED_KEYS


def check_keycloak_jwt_settings(
    *,
    app_configs: Sequence[AppConfig] | None,
    databases: Sequence[str] | None = None,
    **kwargs: Any,
) -> list[CheckMessage]:
    messages: list[CheckMessage] = []
    raw: dict[str, Any] | None = getattr(settings, "KEYCLOAK_JWT", None)

    if raw is None:
        messages.append(
            Error(
                "KEYCLOAK_JWT setting is not configured.",
                hint="Define a KEYCLOAK_JWT dict in your Django settings.",
                id="django_keycloak_jwt.E001",
            )
        )
        return messages

    for key in REQUIRED_KEYS:
        if not raw.get(key):
            messages.append(
                Error(f"KEYCLOAK_JWT[{key!r}] is required.", id="django_keycloak_jwt.E002")
            )

    issuer = raw.get("ISSUER")
    if issuer and not settings.DEBUG and not str(issuer).startswith("https://"):
        messages.append(
            Warning(
                f"KEYCLOAK_JWT['ISSUER'] ({issuer!r}) is not HTTPS while DEBUG=False.",
                hint="Use an https:// issuer in production.",
                id="django_keycloak_jwt.W001",
            )
        )

    algorithms = raw.get("ALGORITHMS", DEFAULTS["ALGORITHMS"])
    forbidden = FORBIDDEN_ALGORITHMS.intersection(algorithms)
    if forbidden:
        messages.append(
            Error(
                f"KEYCLOAK_JWT['ALGORITHMS'] contains forbidden algorithm(s): {sorted(forbidden)}.",
                hint="Only asymmetric algorithms (e.g. RS256) are allowed.",
                id="django_keycloak_jwt.E003",
            )
        )

    unknown = set(raw) - KNOWN_KEYS
    if unknown:
        messages.append(
            Warning(
                f"KEYCLOAK_JWT contains unknown key(s): {sorted(unknown)}.",
                id="django_keycloak_jwt.W002",
            )
        )

    user_model_enabled = raw.get("USER_MODEL_ENABLED", DEFAULTS["USER_MODEL_ENABLED"])
    if user_model_enabled:
        lookup_field = raw.get("USER_MODEL_LOOKUP_FIELD", DEFAULTS["USER_MODEL_LOOKUP_FIELD"])
        if not lookup_field:
            messages.append(
                Error(
                    "KEYCLOAK_JWT['USER_MODEL_LOOKUP_FIELD'] is required when "
                    "KEYCLOAK_JWT['USER_MODEL_ENABLED'] is True.",
                    hint="Set it to a field on AUTH_USER_MODEL matched against "
                    "USER_MODEL_LOOKUP_CLAIM (default 'sub').",
                    id="django_keycloak_jwt.E004",
                )
            )

        field_map = raw.get("USER_MODEL_FIELD_MAP", DEFAULTS["USER_MODEL_FIELD_MAP"])
        if lookup_field and lookup_field in field_map.values():
            messages.append(
                Error(
                    "KEYCLOAK_JWT['USER_MODEL_LOOKUP_FIELD'] must not also appear "
                    "as a USER_MODEL_FIELD_MAP target.",
                    hint="Syncing a claim onto the lookup field would corrupt "
                    "future lookups for that user.",
                    id="django_keycloak_jwt.E005",
                )
            )

        cache_backend = caches["default"].__class__.__module__
        if "locmem" in cache_backend:
            messages.append(
                Warning(
                    "USER_MODEL_ENABLED is True but the default cache backend is "
                    "LocMemCache, which is per-process.",
                    hint="Signal-based cache invalidation on user model changes "
                    "will not be visible to other worker processes. Use a shared "
                    "backend (e.g. Redis or Memcached) in production.",
                    id="django_keycloak_jwt.W003",
                )
            )

    return messages
