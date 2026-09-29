"""Settings loading for ``KEYCLOAK_JWT_CHANNELS``.

Unlike ``KEYCLOAK_JWT``/``KEYCLOAK_JWT_ADMIN``, every key here has a default
-- the dict itself need not be present in Django settings at all. Loaded
lazily and cached, same pattern as the rest of the package.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.signals import setting_changed
from django.dispatch import receiver

DEFAULTS: dict[str, Any] = {
    "SUBPROTOCOL_NAME": "access_token",
    "CLOSE_CODE_TOKEN_INVALID": 4401,
    "CLOSE_CODE_AUTH_UNAVAILABLE": 4503,
    "CLOSE_CODE_TOKEN_EXPIRED": 4001,
}

KNOWN_KEYS = frozenset(DEFAULTS)


@dataclass(frozen=True, slots=True)
class KeycloakJWTChannelsSettings:
    """Resolved, validated ``KEYCLOAK_JWT_CHANNELS`` settings."""

    SUBPROTOCOL_NAME: str
    CLOSE_CODE_TOKEN_INVALID: int
    CLOSE_CODE_AUTH_UNAVAILABLE: int
    CLOSE_CODE_TOKEN_EXPIRED: int


class _Cache:
    settings: KeycloakJWTChannelsSettings | None = None


_lock = threading.Lock()
_cache = _Cache()


def get_channels_settings() -> KeycloakJWTChannelsSettings:
    """Return the resolved settings, loading and caching them on first use."""
    if _cache.settings is None:
        with _lock:
            if _cache.settings is None:
                _cache.settings = _load_settings()
    return _cache.settings


def _load_settings() -> KeycloakJWTChannelsSettings:
    user_settings: dict[str, Any] = getattr(settings, "KEYCLOAK_JWT_CHANNELS", None) or {}
    merged = {**DEFAULTS, **user_settings}

    return KeycloakJWTChannelsSettings(
        SUBPROTOCOL_NAME=merged["SUBPROTOCOL_NAME"],
        CLOSE_CODE_TOKEN_INVALID=merged["CLOSE_CODE_TOKEN_INVALID"],
        CLOSE_CODE_AUTH_UNAVAILABLE=merged["CLOSE_CODE_AUTH_UNAVAILABLE"],
        CLOSE_CODE_TOKEN_EXPIRED=merged["CLOSE_CODE_TOKEN_EXPIRED"],
    )


def reset_channels_settings_cache() -> None:
    """Drop the cached settings so the next access reloads from Django settings."""
    with _lock:
        _cache.settings = None


@receiver(setting_changed)
def _on_setting_changed(*, setting: str, **kwargs: Any) -> None:
    if setting == "KEYCLOAK_JWT_CHANNELS":
        reset_channels_settings_cache()
