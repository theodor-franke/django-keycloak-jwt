"""Framework-agnostic exceptions for the Keycloak JWT validation core.

These carry no request/response objects so ``validation.py`` (and future
Django Channels support) can raise them without depending on DRF or Django.
"""

from __future__ import annotations


class KeycloakJWTError(Exception):
    """Base class for all errors raised by this package."""


class TokenInvalid(KeycloakJWTError):
    """The token failed structural, signature, or claim validation.

    ``reason`` is a short, non-sensitive machine-oriented string (never the
    raw token or key material) suitable for logging and for mapping to an
    HTTP error code.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class TokenExpired(TokenInvalid):
    """The token's ``exp`` claim is in the past (beyond leeway)."""

    def __init__(self, reason: str = "token_expired") -> None:
        super().__init__(reason)


class KeysUnavailable(KeycloakJWTError):
    """The JWKS could not be fetched or parsed, and no usable key is cached.

    Distinct from :class:`TokenInvalid` because it reflects an operational
    failure (network/JWKS outage), not an untrustworthy token, and should
    map to HTTP 503 rather than 401.
    """
