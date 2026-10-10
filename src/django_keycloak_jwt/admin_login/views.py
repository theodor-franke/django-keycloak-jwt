"""Views implementing the Keycloak OIDC login flow for Django admin.

``login`` redirects the browser to Keycloak (Authorization Code + PKCE).
``callback`` exchanges the returned code for tokens, resolves/caches the
local user (:func:`django_keycloak_jwt.user_resolution.resolve_user`),
rejects the login if none of ``USER_MODEL_ROLE_FIELD_MAP``'s fields came out
``True``, and establishes identity for subsequent requests. ``logout`` tears
that identity down and, by default, also redirects through Keycloak's
``end_session_endpoint``.

Two mutually exclusive strategies, selected by ``KEYCLOAK_JWT_ADMIN['COOKIE_MODE']``:

- **Session mode (default).** Validates the returned *ID* token
  (:func:`django_keycloak_jwt.admin_login.oidc.validate_id_token`) and starts
  a real Django session via ``django.contrib.auth.login``. PKCE state lives
  in ``request.session`` between ``login`` and ``callback``.
- **Cookie mode.** Validates the returned *access* token via the same
  stateless core the DRF path uses
  (:func:`django_keycloak_jwt.validation.validate_token`) and stores it
  directly in a cookie, re-validated from scratch on every request by
  :class:`~django_keycloak_jwt.admin_login.cookie_middleware.KeycloakAdminCookieMiddleware`
  -- no session, no server-side identity storage. PKCE state lives in a
  short-lived signed cookie instead of the session, since cookie mode makes
  no assumption that ``django.contrib.sessions`` is even in use for identity.
"""

from __future__ import annotations

import time
import urllib.parse
from typing import TYPE_CHECKING, Any

from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.core import signing
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.urls import reverse

from ..conf import get_settings
from ..exceptions import TokenExpired, TokenInvalid, UserNotFound
from ..user_resolution import resolve_user
from ..validation import validate_token
from . import oidc
from .backends import BACKEND_PATH
from .conf import get_admin_settings
from .exceptions import TokenExchangeFailed

if TYPE_CHECKING:
    from .conf import KeycloakJWTAdminSettings

SESSION_STATE_KEY = "keycloak_admin_login_state"
SESSION_VERIFIER_KEY = "keycloak_admin_login_verifier"
SESSION_NEXT_KEY = "keycloak_admin_login_next"
SESSION_REFRESH_TOKEN_KEY = "keycloak_admin_refresh_token"
SESSION_TOKEN_EXP_KEY = "keycloak_admin_token_exp"
SESSION_ID_TOKEN_KEY = "keycloak_admin_id_token"

#: Salt for the cookie-mode login handshake cookie (state + PKCE verifier +
#: post-login ``next``) -- distinct from any other ``django.core.signing``
#: use in the package so a signed value can never be replayed across uses.
STATE_COOKIE_SALT = "django_keycloak_jwt.admin_login.state"


def login(request: HttpRequest) -> HttpResponse:
    kc_settings = get_settings()
    admin_settings = get_admin_settings()
    endpoints = oidc.resolve_endpoints(kc_settings.ISSUER, admin_settings)

    verifier, challenge = oidc.generate_pkce_pair()
    state = oidc.generate_state()
    next_url = request.GET.get("next") or admin_settings.LOGIN_REDIRECT_URL

    redirect_uri = request.build_absolute_uri(reverse("keycloak_admin_login:callback"))
    url = oidc.build_authorization_url(
        endpoints=endpoints,
        client_id=admin_settings.CLIENT_ID,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=challenge,
        scope=admin_settings.SCOPE,
    )
    response = redirect(url)

    if admin_settings.COOKIE_MODE:
        signed = signing.dumps(
            {"state": state, "verifier": verifier, "next": next_url}, salt=STATE_COOKIE_SALT
        )
        response.set_cookie(
            admin_settings.STATE_COOKIE_NAME,
            signed,
            max_age=admin_settings.STATE_COOKIE_MAX_AGE,
            httponly=True,
            secure=admin_settings.ACCESS_COOKIE_SECURE,
            samesite=admin_settings.ACCESS_COOKIE_SAMESITE,
        )
    else:
        request.session[SESSION_STATE_KEY] = state
        request.session[SESSION_VERIFIER_KEY] = verifier
        request.session[SESSION_NEXT_KEY] = next_url

    return response


def _read_state_cookie(
    request: HttpRequest, admin_settings: KeycloakJWTAdminSettings
) -> tuple[str | None, str | None, str]:
    """Return ``(state, verifier, next_url)`` from the signed state cookie.

    A missing cookie is treated the same as an empty session in session mode
    (returns ``None``s so the caller's state-mismatch check rejects the
    request uniformly) -- only a *present but invalid* cookie raises.
    """
    raw = request.COOKIES.get(admin_settings.STATE_COOKIE_NAME)
    if raw is None:
        return None, None, admin_settings.LOGIN_REDIRECT_URL

    payload: dict[str, str] = signing.loads(
        raw, salt=STATE_COOKIE_SALT, max_age=admin_settings.STATE_COOKIE_MAX_AGE
    )
    return payload["state"], payload["verifier"], payload["next"]


def callback(request: HttpRequest) -> HttpResponse:
    admin_settings = get_admin_settings()

    if admin_settings.COOKIE_MODE:
        try:
            expected_state, verifier, next_url = _read_state_cookie(request, admin_settings)
        except signing.BadSignature:
            return HttpResponseBadRequest("Invalid or expired login attempt. Please try again.")
    else:
        expected_state = request.session.pop(SESSION_STATE_KEY, None)
        verifier = request.session.pop(SESSION_VERIFIER_KEY, None)
        next_url = request.session.pop(SESSION_NEXT_KEY, admin_settings.LOGIN_REDIRECT_URL)

    error = request.GET.get("error")
    if error:
        return HttpResponseBadRequest(f"Keycloak login failed: {error}")

    state = request.GET.get("state")
    code = request.GET.get("code")
    if not state or not code or not verifier or state != expected_state:
        return HttpResponseBadRequest("Invalid or expired login attempt. Please try again.")

    kc_settings = get_settings()
    endpoints = oidc.resolve_endpoints(kc_settings.ISSUER, admin_settings)
    redirect_uri = request.build_absolute_uri(reverse("keycloak_admin_login:callback"))

    try:
        tokens = oidc.exchange_code(
            endpoints=endpoints,
            client_id=admin_settings.CLIENT_ID,
            redirect_uri=redirect_uri,
            code=code,
            code_verifier=verifier,
            timeout=admin_settings.HTTP_TIMEOUT,
        )
    except TokenExchangeFailed as exc:
        return HttpResponse(f"Could not reach Keycloak's token endpoint: {exc}", status=503)

    if admin_settings.COOKIE_MODE:
        return _finish_login_cookie(tokens, next_url, admin_settings)
    return _finish_login(request, tokens, next_url)


def _finish_login(request: HttpRequest, tokens: dict[str, Any], next_url: str) -> HttpResponse:
    id_token = tokens.get("id_token")
    if not id_token:
        return HttpResponseBadRequest("Keycloak did not return an ID token.")

    try:
        claims = oidc.validate_id_token(id_token)
    except (TokenInvalid, TokenExpired) as exc:
        return HttpResponseBadRequest(f"Invalid ID token: {exc}")

    try:
        user = resolve_user(claims)
    except UserNotFound:
        return HttpResponse(
            "Your Keycloak account is not provisioned for admin access.", status=403
        )
    except TokenInvalid as exc:
        return HttpResponseBadRequest(f"Invalid token: {exc}")

    role_map = get_settings().USER_MODEL_ROLE_FIELD_MAP
    if not any(getattr(user, field_name) for field_name in role_map.values()):
        return HttpResponse("Your Keycloak account has no admin role assigned.", status=403)

    django_login(request, user, backend=BACKEND_PATH)  # type: ignore[arg-type]
    request.session[SESSION_ID_TOKEN_KEY] = id_token

    refresh_token = tokens.get("refresh_token")
    if refresh_token:
        request.session[SESSION_REFRESH_TOKEN_KEY] = refresh_token

    expires_in = tokens.get("expires_in")
    if isinstance(expires_in, int):
        request.session[SESSION_TOKEN_EXP_KEY] = time.time() + expires_in
        request.session.set_expiry(expires_in)

    return redirect(next_url)


def _finish_login_cookie(
    tokens: dict[str, Any], next_url: str, admin_settings: KeycloakJWTAdminSettings
) -> HttpResponse:
    access_token = tokens.get("access_token")
    if not access_token:
        return HttpResponseBadRequest("Keycloak did not return an access token.")

    try:
        claims = validate_token(access_token)
    except (TokenInvalid, TokenExpired) as exc:
        return HttpResponseBadRequest(f"Invalid access token: {exc}")

    try:
        user = resolve_user(claims)
    except UserNotFound:
        return HttpResponse(
            "Your Keycloak account is not provisioned for admin access.", status=403
        )
    except TokenInvalid as exc:
        return HttpResponseBadRequest(f"Invalid token: {exc}")

    role_map = get_settings().USER_MODEL_ROLE_FIELD_MAP
    if not any(getattr(user, field_name) for field_name in role_map.values()):
        return HttpResponse("Your Keycloak account has no admin role assigned.", status=403)

    response = redirect(next_url)
    response.delete_cookie(admin_settings.STATE_COOKIE_NAME)
    # The cookie never outlives the token it carries -- no separate, longer
    # cookie lifetime to reason about (mirrors session mode's "the session
    # tracks the token, not the other way around").
    max_age = max(int(claims["exp"] - time.time()), 0)
    response.set_cookie(
        admin_settings.ACCESS_COOKIE_NAME,
        access_token,
        max_age=max_age,
        httponly=True,
        secure=admin_settings.ACCESS_COOKIE_SECURE,
        samesite=admin_settings.ACCESS_COOKIE_SAMESITE,
        path=admin_settings.ACCESS_COOKIE_PATH,
    )
    return response


def logout(request: HttpRequest) -> HttpResponse:
    admin_settings = get_admin_settings()
    kc_settings = get_settings()

    if admin_settings.COOKIE_MODE:
        # No session-based identity to tear down, and no ID token was ever
        # stored to pass as id_token_hint -- the cookie carries only the
        # access token.
        id_token_hint = None
    else:
        id_token_hint = request.session.pop(SESSION_ID_TOKEN_KEY, None)
        django_logout(request)

    response: HttpResponse | None = None
    if admin_settings.LOGOUT_END_SESSION:
        endpoints = oidc.resolve_endpoints(kc_settings.ISSUER, admin_settings)
        end_session_endpoint = endpoints.get("end_session_endpoint")
        if end_session_endpoint:
            redirect_uri = request.build_absolute_uri(admin_settings.LOGIN_REDIRECT_URL)
            params = {
                "post_logout_redirect_uri": redirect_uri,
                "client_id": admin_settings.CLIENT_ID,
            }
            if id_token_hint:
                params["id_token_hint"] = id_token_hint
            response = redirect(f"{end_session_endpoint}?{urllib.parse.urlencode(params)}")

    if response is None:
        response = redirect(admin_settings.LOGIN_REDIRECT_URL)

    if admin_settings.COOKIE_MODE:
        response.delete_cookie(
            admin_settings.ACCESS_COOKIE_NAME, path=admin_settings.ACCESS_COOKIE_PATH
        )

    return response
