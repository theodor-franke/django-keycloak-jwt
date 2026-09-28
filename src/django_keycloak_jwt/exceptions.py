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


class DiscoveryUnavailable(KeycloakJWTError):
    """The OIDC discovery document could not be fetched or parsed.

    Raised by :mod:`django_keycloak_jwt.discovery` when
    ``.well-known/openid-configuration`` is unreachable or malformed and no
    document is already cached for that issuer.
    """


class UserNotFound(KeycloakJWTError):
    """``USER_MODEL_ENABLED`` is True, ``USER_MODEL_AUTO_CREATE`` is False,
    and no local user row matches the token's claims.

    Distinct from :class:`TokenInvalid` because the token itself is valid —
    the local user simply hasn't been provisioned.
    """
