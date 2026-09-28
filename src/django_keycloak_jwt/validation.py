"""Framework-agnostic token validation core.

``validate_token`` takes a raw bearer token string and returns its verified
claims, or raises one of the exceptions in :mod:`django_keycloak_jwt.exceptions`.
No Django request objects, no DRF imports — this module is reused as-is by
any future Django Channels integration.
"""

from __future__ import annotations

from typing import Any

import jwt
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from . import jwks
from .conf import KeycloakJWTSettings, get_settings
from .exceptions import TokenExpired, TokenInvalid

#: Claims that must be present in every access token, regardless of value.
REQUIRED_CLAIMS = ["exp", "iat", "iss", "sub", "aud"]


def validate_token(raw: str) -> dict[str, Any]:
    """Validate a raw ``Authorization: Bearer`` token and return its claims.

    Raises :class:`~django_keycloak_jwt.exceptions.TokenInvalid`,
    :class:`~django_keycloak_jwt.exceptions.TokenExpired`, or
    :class:`~django_keycloak_jwt.exceptions.KeysUnavailable`.
    """
    return _validate_token(raw, get_settings())


def _validate_token(raw: str, settings: KeycloakJWTSettings) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(raw)
    except PyJWTError as exc:
        raise TokenInvalid("malformed_header") from exc

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in settings.ALGORITHMS:
        raise TokenInvalid("algorithm_not_allowed")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenInvalid("missing_kid")

    # May itself raise TokenInvalid (unknown kid) or KeysUnavailable.
    signing_key = jwks.get_signing_key(settings, kid, alg)

    try:
        claims = jwt.decode(
            raw,
            key=signing_key,
            algorithms=settings.ALGORITHMS,
            audience=settings.audiences,
            issuer=settings.ISSUER,
            leeway=settings.LEEWAY,
            options={"require": REQUIRED_CLAIMS},
        )
    except ExpiredSignatureError as exc:
        raise TokenExpired() from exc
    except PyJWTError as exc:
        raise TokenInvalid(exc.__class__.__name__) from exc

    if claims.get("typ") != settings.REQUIRED_TYP:
        raise TokenInvalid("unexpected_typ")

    if settings.ALLOWED_AZP is not None and claims.get("azp") not in settings.ALLOWED_AZP:
        raise TokenInvalid("azp_not_allowed")

    return claims
