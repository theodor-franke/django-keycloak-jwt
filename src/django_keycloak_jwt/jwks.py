"""JWKS fetching and caching, with rotation handling.

A thin wrapper around :class:`jwt.PyJWKClient` that adds what it doesn't
provide out of the box:

- matching candidate keys by both ``kid`` *and* ``alg`` (PyJWKClient only
  matches ``kid``),
- a dedicated, independently observable rate limit on refetches triggered
  by an unknown ``kid`` (``JWKS_MIN_REFETCH_INTERVAL``) — a DoS guard
  against random ``kid``s forcing unlimited outbound requests,
- mapping network/parse failures to :class:`~django_keycloak_jwt.exceptions.KeysUnavailable`
  instead of letting PyJWT's own exception types leak out,
- stale-while-error: serving a previously good key for a known ``kid`` if
  a refetch fails, with a warning log (never a raw token or key material).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

import jwt
from jwt import PyJWK

from . import __version__
from .exceptions import KeysUnavailable, TokenInvalid

if TYPE_CHECKING:
    from .conf import KeycloakJWTSettings

logger = logging.getLogger("django_keycloak_jwt")

USER_AGENT = f"django-keycloak-jwt/{__version__}"


class _JWKSCache:
    """Signing-key cache for a single JWKS URL. Internally thread-safe."""

    def __init__(self, kc_settings: KeycloakJWTSettings) -> None:
        self._client = jwt.PyJWKClient(
            kc_settings.JWKS_URL,
            cache_keys=False,
            cache_jwk_set=True,
            lifespan=kc_settings.JWKS_CACHE_LIFESPAN,
            headers={"User-Agent": USER_AGENT},
            timeout=kc_settings.HTTP_TIMEOUT,
            cooldown_duration=0,
        )
        self._min_refetch_interval = kc_settings.JWKS_MIN_REFETCH_INTERVAL
        self._lock = threading.Lock()
        self._last_good: dict[str, PyJWK] = {}
        self._last_forced_refetch_at: float | None = None

    def get_signing_key(self, kid: str, alg: str) -> PyJWK:
        with self._lock:
            try:
                keys = self._client.get_signing_keys()
            except Exception as exc:
                return self._stale_or_raise(kid, exc)

            match = self._match(keys, kid, alg)
            if match is not None:
                self._remember(keys)
                return match

            if not self._can_force_refetch():
                raise TokenInvalid("unknown_kid")

            self._last_forced_refetch_at = time.monotonic()
            try:
                keys = self._client.get_signing_keys(refresh=True)
            except Exception as exc:
                return self._stale_or_raise(kid, exc)

            self._remember(keys)
            match = self._match(keys, kid, alg)
            if match is None:
                raise TokenInvalid("unknown_kid")
            return match

    def _can_force_refetch(self) -> bool:
        if self._last_forced_refetch_at is None:
            return True
        return time.monotonic() - self._last_forced_refetch_at >= self._min_refetch_interval

    @staticmethod
    def _match(keys: list[PyJWK], kid: str, alg: str) -> PyJWK | None:
        for key in keys:
            if key.key_id == kid and key.algorithm_name == alg:
                return key
        return None

    def _remember(self, keys: list[PyJWK]) -> None:
        self._last_good.update({key.key_id: key for key in keys if key.key_id})

    def _stale_or_raise(self, kid: str, exc: Exception) -> PyJWK:
        stale = self._last_good.get(kid)
        if stale is not None:
            logger.warning(
                "JWKS refetch failed (%s); using stale cached key for kid=%s",
                exc.__class__.__name__,
                kid,
            )
            return stale
        raise KeysUnavailable(f"JWKS unavailable: {exc.__class__.__name__}") from exc


_registry: dict[str, _JWKSCache] = {}
_registry_lock = threading.Lock()


def _cache_for(kc_settings: KeycloakJWTSettings) -> _JWKSCache:
    url = kc_settings.JWKS_URL
    with _registry_lock:
        cache = _registry.get(url)
        if cache is None:
            cache = _JWKSCache(kc_settings)
            _registry[url] = cache
        return cache


def get_signing_key(kc_settings: KeycloakJWTSettings, kid: str, alg: str) -> PyJWK:
    """Resolve the signing key for *kid* / *alg* under the given settings.

    Raises :class:`~django_keycloak_jwt.exceptions.TokenInvalid` for an unknown
    ``kid`` (rate-limited refetch already attempted or on cooldown) and
    :class:`~django_keycloak_jwt.exceptions.KeysUnavailable` if the JWKS cannot be
    fetched or parsed and no stale key is available.
    """
    return _cache_for(kc_settings).get_signing_key(kid, alg)


def reset_jwks_cache() -> None:
    """Drop all cached JWKS state for every URL. Intended for use in tests."""
    with _registry_lock:
        _registry.clear()
