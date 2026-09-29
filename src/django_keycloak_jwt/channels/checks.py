"""Django system checks for ``KEYCLOAK_JWT_CHANNELS`` misconfiguration."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.conf import settings
from django.core.checks import CheckMessage, Error, Warning

from .conf import DEFAULTS, KNOWN_KEYS

#: RFC 6455 7.4.2: 4000-4999 is reserved for private use.
_VALID_CODE_RANGE = range(4000, 5000)

_CODE_KEYS = (
    "CLOSE_CODE_TOKEN_INVALID",
    "CLOSE_CODE_AUTH_UNAVAILABLE",
    "CLOSE_CODE_TOKEN_EXPIRED",
)


def check_keycloak_jwt_channels_settings(
    *,
    app_configs: Sequence[AppConfig] | None,
    databases: Sequence[str] | None = None,
    **kwargs: Any,
) -> list[CheckMessage]:
    messages: list[CheckMessage] = []
    raw: dict[str, Any] = getattr(settings, "KEYCLOAK_JWT_CHANNELS", None) or {}

    unknown = set(raw) - KNOWN_KEYS
    if unknown:
        messages.append(
            Warning(
                f"KEYCLOAK_JWT_CHANNELS contains unknown key(s): {sorted(unknown)}.",
                id="django_keycloak_jwt.channels.W001",
            )
        )

    codes: dict[str, int] = {}
    for key in _CODE_KEYS:
        value = raw.get(key, DEFAULTS[key])
        codes[key] = value
        if value not in _VALID_CODE_RANGE:
            messages.append(
                Error(
                    f"KEYCLOAK_JWT_CHANNELS[{key!r}] ({value!r}) must be in the "
                    "4000-4999 private-use range (RFC 6455 7.4.2).",
                    id="django_keycloak_jwt.channels.E001",
                )
            )

    if len(set(codes.values())) != len(codes):
        messages.append(
            Warning(
                "KEYCLOAK_JWT_CHANNELS close codes are not all distinct "
                f"({codes}) -- clients won't be able to tell the failure reasons apart.",
                id="django_keycloak_jwt.channels.W002",
            )
        )

    subprotocol_name = raw.get("SUBPROTOCOL_NAME", DEFAULTS["SUBPROTOCOL_NAME"])
    if not subprotocol_name or not isinstance(subprotocol_name, str):
        messages.append(
            Error(
                "KEYCLOAK_JWT_CHANNELS['SUBPROTOCOL_NAME'] must be a non-empty string.",
                id="django_keycloak_jwt.channels.E002",
            )
        )

    return messages
