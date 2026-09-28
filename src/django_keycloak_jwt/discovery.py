"""OIDC discovery document fetching and caching.

Used by the optional ``admin_login`` module to resolve a realm's
``authorization_endpoint``/``token_endpoint``/``end_session_endpoint``
without requiring them to be configured by hand. Mirrors ``jwks.py``'s
approach: fetched lazily on first use (never at Django startup, so
``manage.py`` commands never block on a Keycloak round-trip), cached
in-process for the app's lifetime since these endpoints do not change in
practice, using the stdlib's ``urllib`` (the same HTTP layer PyJWT's
``PyJWKClient`` already uses internally) rather than adding a new runtime
dependency.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any

from . import __version__
from .exceptions import DiscoveryUnavailable

USER_AGENT = f"django-keycloak-jwt/{__version__}"

_registry: dict[str, dict[str, Any]] = {}
_registry_lock = threading.Lock()


def get_discovery_document(issuer: str, *, timeout: int = 5) -> dict[str, Any]:
    """Return the cached OIDC discovery document for *issuer*.

    Fetches and caches it on first use. Raises
    :class:`~django_keycloak_jwt.exceptions.DiscoveryUnavailable` if the
    document cannot be fetched or parsed and none is cached yet.
    """
    with _registry_lock:
        document = _registry.get(issuer)
        if document is not None:
            return document

    fetched = _fetch(issuer, timeout)

    with _registry_lock:
        return _registry.setdefault(issuer, fetched)


def _fetch(issuer: str, timeout: int) -> dict[str, Any]:
    url = f"{issuer}/.well-known/openid-configuration"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise DiscoveryUnavailable(
            f"OIDC discovery document unavailable: {exc.__class__.__name__}"
        ) from exc

    try:
        document = json.loads(body)
    except json.JSONDecodeError as exc:
        raise DiscoveryUnavailable(f"OIDC discovery document is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise DiscoveryUnavailable("OIDC discovery document is not a JSON object.")

    return document


def reset_discovery_cache() -> None:
    """Drop all cached discovery documents. Intended for use in tests."""
    with _registry_lock:
        _registry.clear()
