"""Settings loading, defaults, and validation for ``KEYCLOAK_JWT``.

A single dict named ``KEYCLOAK_JWT`` in the Django settings module. Loaded
lazily on first use, cached, and reset whenever Django's ``setting_changed``
signal fires (so ``override_settings(KEYCLOAK_JWT=...)`` works in tests).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.dispatch import receiver

#: Algorithms that must never be accepted, regardless of configuration.
FORBIDDEN_ALGORITHMS = frozenset({"none", "HS256", "HS384", "HS512"})

DEFAULTS: dict[str, Any] = {
    "JWKS_URL": None,
    "ALGORITHMS": ["RS256"],
    "LEEWAY": 10,
    "ALLOWED_AZP": None,
    "REQUIRED_TYP": "Bearer",
    "ROLE_CLIENT": None,
    "JWKS_CACHE_LIFESPAN": 300,
    "JWKS_MIN_REFETCH_INTERVAL": 30,
    "HTTP_TIMEOUT": 5,
    "USER_CLASS": "django_keycloak_jwt.principal.KeycloakUser",
    "AUTH_HEADER_REALM": "api",
    "USER_MODEL_ENABLED": False,
    "USER_MODEL_LOOKUP_CLAIM": "sub",
    "USER_MODEL_LOOKUP_FIELD": None,
    "USER_MODEL_FIELD_MAP": {
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
    },
    "USER_MODEL_AUTO_CREATE": True,
    "USER_MODEL_CACHE_TTL": 300,
    "USER_MODEL_ROLE_FIELD_MAP": {},
}

REQUIRED_KEYS = ("ISSUER", "AUDIENCE")

KNOWN_KEYS = frozenset({*DEFAULTS, *REQUIRED_KEYS})


@dataclass(frozen=True, slots=True)
class KeycloakJWTSettings:
    """Resolved, validated ``KEYCLOAK_JWT`` settings."""

    ISSUER: str
    AUDIENCE: str | list[str]
    JWKS_URL: str
    ALGORITHMS: list[str]
    LEEWAY: int
    ALLOWED_AZP: list[str] | None
    REQUIRED_TYP: str
    ROLE_CLIENT: str | None
    JWKS_CACHE_LIFESPAN: int
    JWKS_MIN_REFETCH_INTERVAL: int
    HTTP_TIMEOUT: int
    USER_CLASS: str
    AUTH_HEADER_REALM: str
    USER_MODEL_ENABLED: bool
    USER_MODEL_LOOKUP_CLAIM: str
    USER_MODEL_LOOKUP_FIELD: str | None
    USER_MODEL_FIELD_MAP: dict[str, str]
    USER_MODEL_AUTO_CREATE: bool
    USER_MODEL_CACHE_TTL: int
    USER_MODEL_ROLE_FIELD_MAP: dict[str, str]

    @property
    def audiences(self) -> list[str]:
        """``AUDIENCE`` normalized to a list."""
        return [self.AUDIENCE] if isinstance(self.AUDIENCE, str) else list(self.AUDIENCE)


class _Cache:
    settings: KeycloakJWTSettings | None = None


_lock = threading.Lock()
_cache = _Cache()


def get_settings() -> KeycloakJWTSettings:
    """Return the resolved settings, loading and caching them on first use."""
    if _cache.settings is None:
        with _lock:
            if _cache.settings is None:
                _cache.settings = _load_settings()
    return _cache.settings


def _load_settings() -> KeycloakJWTSettings:
    user_settings: dict[str, Any] | None = getattr(settings, "KEYCLOAK_JWT", None)
    if user_settings is None:
        raise ImproperlyConfigured("The KEYCLOAK_JWT setting is required.")

    for key in REQUIRED_KEYS:
        if not user_settings.get(key):
            raise ImproperlyConfigured(f"KEYCLOAK_JWT[{key!r}] is required.")

    merged = {**DEFAULTS, **user_settings}

    algorithms = list(merged["ALGORITHMS"])
    forbidden = FORBIDDEN_ALGORITHMS.intersection(algorithms)
    if forbidden:
        raise ImproperlyConfigured(
            f"KEYCLOAK_JWT['ALGORITHMS'] contains forbidden algorithm(s): {sorted(forbidden)}."
        )

    jwks_url = merged["JWKS_URL"] or f"{merged['ISSUER']}/protocol/openid-connect/certs"

    if merged["USER_MODEL_ENABLED"]:
        if not merged["USER_MODEL_LOOKUP_FIELD"]:
            raise ImproperlyConfigured(
                "KEYCLOAK_JWT['USER_MODEL_LOOKUP_FIELD'] is required when "
                "KEYCLOAK_JWT['USER_MODEL_ENABLED'] is True."
            )
        if merged["USER_MODEL_LOOKUP_FIELD"] in merged["USER_MODEL_FIELD_MAP"].values():
            raise ImproperlyConfigured(
                "KEYCLOAK_JWT['USER_MODEL_LOOKUP_FIELD'] must not also appear as a "
                "USER_MODEL_FIELD_MAP target -- syncing a claim onto the lookup "
                "field would corrupt future lookups for that user."
            )

    return KeycloakJWTSettings(
        ISSUER=merged["ISSUER"],
        AUDIENCE=merged["AUDIENCE"],
        JWKS_URL=jwks_url,
        ALGORITHMS=algorithms,
        LEEWAY=merged["LEEWAY"],
        ALLOWED_AZP=merged["ALLOWED_AZP"],
        REQUIRED_TYP=merged["REQUIRED_TYP"],
        ROLE_CLIENT=merged["ROLE_CLIENT"],
        JWKS_CACHE_LIFESPAN=merged["JWKS_CACHE_LIFESPAN"],
        JWKS_MIN_REFETCH_INTERVAL=merged["JWKS_MIN_REFETCH_INTERVAL"],
        HTTP_TIMEOUT=merged["HTTP_TIMEOUT"],
        USER_CLASS=merged["USER_CLASS"],
        AUTH_HEADER_REALM=merged["AUTH_HEADER_REALM"],
        USER_MODEL_ENABLED=merged["USER_MODEL_ENABLED"],
        USER_MODEL_LOOKUP_CLAIM=merged["USER_MODEL_LOOKUP_CLAIM"],
        USER_MODEL_LOOKUP_FIELD=merged["USER_MODEL_LOOKUP_FIELD"],
        USER_MODEL_FIELD_MAP=dict(merged["USER_MODEL_FIELD_MAP"]),
        USER_MODEL_AUTO_CREATE=merged["USER_MODEL_AUTO_CREATE"],
        USER_MODEL_CACHE_TTL=merged["USER_MODEL_CACHE_TTL"],
        USER_MODEL_ROLE_FIELD_MAP=dict(merged["USER_MODEL_ROLE_FIELD_MAP"]),
    )


def reset_settings_cache() -> None:
    """Drop the cached settings so the next access reloads from Django settings."""
    with _lock:
        _cache.settings = None


@receiver(setting_changed)
def _on_setting_changed(*, setting: str, **kwargs: Any) -> None:
    if setting == "KEYCLOAK_JWT":
        reset_settings_cache()
