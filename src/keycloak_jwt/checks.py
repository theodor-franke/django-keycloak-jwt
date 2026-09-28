"""Django system checks for ``KEYCLOAK_JWT`` misconfiguration."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from django.apps import AppConfig
from django.conf import settings
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
                id="keycloak_jwt.E001",
            )
        )
        return messages

    for key in REQUIRED_KEYS:
        if not raw.get(key):
            messages.append(Error(f"KEYCLOAK_JWT[{key!r}] is required.", id="keycloak_jwt.E002"))

    issuer = raw.get("ISSUER")
    if issuer and not settings.DEBUG and not str(issuer).startswith("https://"):
        messages.append(
            Warning(
                f"KEYCLOAK_JWT['ISSUER'] ({issuer!r}) is not HTTPS while DEBUG=False.",
                hint="Use an https:// issuer in production.",
                id="keycloak_jwt.W001",
            )
        )

    algorithms = raw.get("ALGORITHMS", DEFAULTS["ALGORITHMS"])
    forbidden = FORBIDDEN_ALGORITHMS.intersection(algorithms)
    if forbidden:
        messages.append(
            Error(
                f"KEYCLOAK_JWT['ALGORITHMS'] contains forbidden algorithm(s): {sorted(forbidden)}.",
                hint="Only asymmetric algorithms (e.g. RS256) are allowed.",
                id="keycloak_jwt.E003",
            )
        )

    unknown = set(raw) - KNOWN_KEYS
    if unknown:
        messages.append(
            Warning(
                f"KEYCLOAK_JWT contains unknown key(s): {sorted(unknown)}.",
                id="keycloak_jwt.W002",
            )
        )

    return messages
