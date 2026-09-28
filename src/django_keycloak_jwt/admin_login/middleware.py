"""Silently refreshes a Keycloak-backed admin session near token expiry.

Self-gating: a no-op for any request whose session carries no Keycloak
admin login state, so it's safe to add to ``MIDDLEWARE`` globally rather
than scoping it to ``/admin/``. On refresh failure (network error, invalid
response, expired refresh token) the session is logged out and the next
admin request's normal "login required" redirect restarts the OIDC flow.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from django.contrib.auth import logout as django_logout

from ..conf import get_settings
from ..exceptions import DiscoveryUnavailable, TokenExpired, TokenInvalid
from ..user_resolution import resolve_user
from . import oidc
from .conf import get_admin_settings
from .exceptions import TokenExchangeFailed
from .views import (
    SESSION_ID_TOKEN_KEY,
    SESSION_REFRESH_TOKEN_KEY,
    SESSION_TOKEN_EXP_KEY,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse

#: Exceptions that mean "the refresh attempt failed cleanly" -- log out and
#: let the normal login-required redirect restart the flow, rather than
#: propagating a 500.
_REFRESH_FAILURE_EXCEPTIONS = (
    TokenExchangeFailed,
    TokenInvalid,
    TokenExpired,
    DiscoveryUnavailable,
    KeyError,
)


class KeycloakAdminSessionMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self._maybe_refresh(request)
        return self.get_response(request)

    def _maybe_refresh(self, request: HttpRequest) -> None:
        session = getattr(request, "session", None)
        if session is None:
            return

        refresh_token = session.get(SESSION_REFRESH_TOKEN_KEY)
        exp = session.get(SESSION_TOKEN_EXP_KEY)
        if not refresh_token or not exp:
            return

        admin_settings = get_admin_settings()
        if time.time() < exp - admin_settings.REFRESH_LEEWAY:
            return

        kc_settings = get_settings()
        endpoints = oidc.resolve_endpoints(kc_settings.ISSUER, admin_settings)

        try:
            tokens = oidc.refresh_tokens(
                endpoints=endpoints,
                client_id=admin_settings.CLIENT_ID,
                refresh_token=refresh_token,
                timeout=admin_settings.HTTP_TIMEOUT,
            )
            id_token = tokens["id_token"]
            claims = oidc.validate_id_token(id_token)
            user = resolve_user(claims)
        except _REFRESH_FAILURE_EXCEPTIONS:
            django_logout(request)
            return

        request.user = user  # type: ignore[assignment]
        session[SESSION_ID_TOKEN_KEY] = id_token
        session[SESSION_REFRESH_TOKEN_KEY] = tokens.get("refresh_token", refresh_token)

        expires_in = tokens.get("expires_in")
        if isinstance(expires_in, int):
            session[SESSION_TOKEN_EXP_KEY] = time.time() + expires_in
            session.set_expiry(expires_in)
