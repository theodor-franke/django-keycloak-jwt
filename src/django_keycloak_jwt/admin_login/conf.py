"""Settings loading for ``KEYCLOAK_JWT_ADMIN``.

A dict separate from ``KEYCLOAK_JWT`` so the core package stays a pure,
unconfigured resource server for anyone who doesn't install
``django_keycloak_jwt.admin_login``. Loaded lazily and cached, same pattern
as ``django_keycloak_jwt.conf``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Literal

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.dispatch import receiver

DEFAULTS: dict[str, Any] = {
    "AUTHORIZATION_ENDPOINT": None,
    "TOKEN_ENDPOINT": None,
    "END_SESSION_ENDPOINT": None,
    "LOGOUT_END_SESSION": True,
    "SCOPE": "openid",
    "HTTP_TIMEOUT": 5,
    "LOGIN_REDIRECT_URL": "/admin/",
    "REFRESH_LEEWAY": 30,
    "COOKIE_MODE": False,
    "ACCESS_COOKIE_NAME": "kc_admin_access_token",
    "ACCESS_COOKIE_PATH": "/",
    "ACCESS_COOKIE_SECURE": True,
    "ACCESS_COOKIE_SAMESITE": "Lax",
    "STATE_COOKIE_NAME": "kc_admin_login_state",
    "STATE_COOKIE_MAX_AGE": 300,
}

#: Public client ID for the dedicated admin OIDC client (PKCE, no secret).
REQUIRED_KEYS = ("CLIENT_ID",)

KNOWN_KEYS = frozenset({*DEFAULTS, *REQUIRED_KEYS})


@dataclass(frozen=True, slots=True)
class KeycloakJWTAdminSettings:
    """Resolved, validated ``KEYCLOAK_JWT_ADMIN`` settings."""

    CLIENT_ID: str
    AUTHORIZATION_ENDPOINT: str | None
    TOKEN_ENDPOINT: str | None
    END_SESSION_ENDPOINT: str | None
    LOGOUT_END_SESSION: bool
    SCOPE: str
    HTTP_TIMEOUT: int
    LOGIN_REDIRECT_URL: str
    REFRESH_LEEWAY: int
    COOKIE_MODE: bool
    ACCESS_COOKIE_NAME: str
    ACCESS_COOKIE_PATH: str
    ACCESS_COOKIE_SECURE: bool
    ACCESS_COOKIE_SAMESITE: Literal["Lax", "Strict", "None"]
    STATE_COOKIE_NAME: str
    STATE_COOKIE_MAX_AGE: int


class _Cache:
    settings: KeycloakJWTAdminSettings | None = None


_lock = threading.Lock()
_cache = _Cache()


def get_admin_settings() -> KeycloakJWTAdminSettings:
    """Return the resolved settings, loading and caching them on first use."""
    if _cache.settings is None:
        with _lock:
            if _cache.settings is None:
                _cache.settings = _load_settings()
    return _cache.settings


def _load_settings() -> KeycloakJWTAdminSettings:
    user_settings: dict[str, Any] | None = getattr(settings, "KEYCLOAK_JWT_ADMIN", None)
    if user_settings is None:
        raise ImproperlyConfigured("The KEYCLOAK_JWT_ADMIN setting is required.")

    for key in REQUIRED_KEYS:
        if not user_settings.get(key):
            raise ImproperlyConfigured(f"KEYCLOAK_JWT_ADMIN[{key!r}] is required.")

    merged = {**DEFAULTS, **user_settings}

    return KeycloakJWTAdminSettings(
        CLIENT_ID=merged["CLIENT_ID"],
        AUTHORIZATION_ENDPOINT=merged["AUTHORIZATION_ENDPOINT"],
        TOKEN_ENDPOINT=merged["TOKEN_ENDPOINT"],
        END_SESSION_ENDPOINT=merged["END_SESSION_ENDPOINT"],
        LOGOUT_END_SESSION=merged["LOGOUT_END_SESSION"],
        SCOPE=merged["SCOPE"],
        HTTP_TIMEOUT=merged["HTTP_TIMEOUT"],
        LOGIN_REDIRECT_URL=merged["LOGIN_REDIRECT_URL"],
        REFRESH_LEEWAY=merged["REFRESH_LEEWAY"],
        COOKIE_MODE=merged["COOKIE_MODE"],
        ACCESS_COOKIE_NAME=merged["ACCESS_COOKIE_NAME"],
        ACCESS_COOKIE_PATH=merged["ACCESS_COOKIE_PATH"],
        ACCESS_COOKIE_SECURE=merged["ACCESS_COOKIE_SECURE"],
        ACCESS_COOKIE_SAMESITE=merged["ACCESS_COOKIE_SAMESITE"],
        STATE_COOKIE_NAME=merged["STATE_COOKIE_NAME"],
        STATE_COOKIE_MAX_AGE=merged["STATE_COOKIE_MAX_AGE"],
    )


def reset_admin_settings_cache() -> None:
    """Drop the cached settings so the next access reloads from Django settings."""
    with _lock:
        _cache.settings = None


@receiver(setting_changed)
def _on_setting_changed(*, setting: str, **kwargs: Any) -> None:
    if setting == "KEYCLOAK_JWT_ADMIN":
        reset_admin_settings_cache()
