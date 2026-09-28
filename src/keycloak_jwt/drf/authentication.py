"""DRF authentication backend for Keycloak-issued JWTs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils.module_loading import import_string
from rest_framework import status
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import APIException, AuthenticationFailed

from .. import validation
from ..conf import get_settings
from ..exceptions import KeysUnavailable, TokenExpired, TokenInvalid
from ..principal import KeycloakUser

if TYPE_CHECKING:
    from rest_framework.request import Request

#: Expected ``[b"Bearer", b"<token>"]`` length of a well-formed header.
_AUTH_HEADER_PARTS = 2


class AuthUnavailable(APIException):
    """The JWKS could not be fetched/parsed and no stale key was usable."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Authentication service temporarily unavailable."
    default_code = "auth_unavailable"


class KeycloakJWTAuthentication(BaseAuthentication):
    """Authenticates requests bearing a Keycloak-issued RS256 access token.

    Absence of an ``Authorization`` header, or a scheme other than
    ``Bearer``, is not this authenticator's concern: it returns ``None`` so
    other configured authenticators (or anonymous access) can take over.
    """

    def authenticate(self, request: Request) -> tuple[KeycloakUser, str] | None:
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b"bearer":
            return None

        if len(auth) != _AUTH_HEADER_PARTS:
            raise AuthenticationFailed(
                "Invalid Authorization header. Expected 'Bearer <token>'.",
                code="invalid_header",
            )

        try:
            raw_token = auth[1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AuthenticationFailed(
                "Invalid Authorization header encoding.", code="invalid_header"
            ) from exc

        try:
            claims = validation.validate_token(raw_token)
        except TokenExpired as exc:
            raise AuthenticationFailed(exc.reason, code="token_expired") from exc
        except TokenInvalid as exc:
            raise AuthenticationFailed(exc.reason, code="token_not_valid") from exc
        except KeysUnavailable as exc:
            raise AuthUnavailable() from exc

        user_class = import_string(get_settings().USER_CLASS)
        user: KeycloakUser = user_class(claims)
        return user, raw_token

    def authenticate_header(self, request: Request) -> str:
        realm = get_settings().AUTH_HEADER_REALM
        return f'Bearer realm="{realm}"'
