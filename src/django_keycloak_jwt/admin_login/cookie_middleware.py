"""Re-validates a Keycloak access token cookie on every request, from scratch.

Self-gating: a no-op whenever ``COOKIE_MODE`` is off or the request carries
no access-token cookie, so it's safe to add to ``MIDDLEWARE`` globally
rather than scoping it to ``/admin/``. Distinct from
:mod:`django_keycloak_jwt.admin_login.middleware`'s
``KeycloakAdminSessionMiddleware`` (which *refreshes* a session-mode login in
the background): this middleware never writes anything back, never talks to
Keycloak, and never consults ``AUTHENTICATION_BACKENDS`` or
``request.session`` -- it just re-derives identity from the cookie's token
through the same stateless core the DRF path uses
(:func:`django_keycloak_jwt.validation.validate_token` +
:func:`django_keycloak_jwt.user_resolution.resolve_user`), the same way on
every single request. That's what makes cookie mode stateless: there is
nothing here that remembers a prior request.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..exceptions import TokenExpired, TokenInvalid, UserNotFound
from ..user_resolution import resolve_user
from ..validation import validate_token
from .conf import get_admin_settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse


class KeycloakAdminCookieMiddleware:
    """Must run after ``AuthenticationMiddleware`` in ``MIDDLEWARE`` so there
    is already a ``request.user`` (normally ``AnonymousUser``) to override on
    success -- and so that, on failure, it's left exactly as that middleware
    produced it, letting Django admin's own unauthenticated-visitor flow
    (``has_permission`` -> redirect to ``admin:login``) handle an
    expired/missing cookie for free, the same code path as a first-time
    visitor.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        admin_settings = get_admin_settings()
        if admin_settings.COOKIE_MODE:
            token = request.COOKIES.get(admin_settings.ACCESS_COOKIE_NAME)
            if token:
                try:
                    claims = validate_token(token)
                    user = resolve_user(claims)
                except (TokenInvalid, TokenExpired, UserNotFound):
                    pass
                else:
                    request.user = user  # type: ignore[assignment]

        return self.get_response(request)
