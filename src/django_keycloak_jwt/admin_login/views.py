"""Views implementing the Keycloak OIDC login flow for Django admin.

``login`` redirects the browser to Keycloak (Authorization Code + PKCE).
``callback`` exchanges the returned code for tokens, validates the ID
token, resolves/caches the local user (:func:`django_keycloak_jwt.user_resolution.resolve_user`),
rejects the login if none of ``USER_MODEL_ROLE_FIELD_MAP``'s fields came out
``True``, and starts a real Django session. ``logout`` ends that session
and, by default, also redirects through Keycloak's ``end_session_endpoint``.
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Any

from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.urls import reverse

from ..conf import get_settings
from ..exceptions import TokenExpired, TokenInvalid, UserNotFound
from ..user_resolution import resolve_user
from . import oidc
from .backends import BACKEND_PATH
from .conf import get_admin_settings
from .exceptions import TokenExchangeFailed

SESSION_STATE_KEY = "keycloak_admin_login_state"
SESSION_VERIFIER_KEY = "keycloak_admin_login_verifier"
SESSION_NEXT_KEY = "keycloak_admin_login_next"
SESSION_REFRESH_TOKEN_KEY = "keycloak_admin_refresh_token"
SESSION_TOKEN_EXP_KEY = "keycloak_admin_token_exp"
SESSION_ID_TOKEN_KEY = "keycloak_admin_id_token"


def login(request: HttpRequest) -> HttpResponse:
    kc_settings = get_settings()
    admin_settings = get_admin_settings()
    endpoints = oidc.resolve_endpoints(kc_settings.ISSUER, admin_settings)

    verifier, challenge = oidc.generate_pkce_pair()
    state = oidc.generate_state()

    request.session[SESSION_STATE_KEY] = state
    request.session[SESSION_VERIFIER_KEY] = verifier
    request.session[SESSION_NEXT_KEY] = request.GET.get("next") or admin_settings.LOGIN_REDIRECT_URL

    redirect_uri = request.build_absolute_uri(reverse("keycloak_admin_login:callback"))
    url = oidc.build_authorization_url(
        endpoints=endpoints,
        client_id=admin_settings.CLIENT_ID,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=challenge,
        scope=admin_settings.SCOPE,
    )
    return redirect(url)


def callback(request: HttpRequest) -> HttpResponse:
    admin_settings = get_admin_settings()

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


def logout(request: HttpRequest) -> HttpResponse:
    admin_settings = get_admin_settings()
    kc_settings = get_settings()
    id_token_hint = request.session.pop(SESSION_ID_TOKEN_KEY, None)
    django_logout(request)

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
            return redirect(f"{end_session_endpoint}?{urllib.parse.urlencode(params)}")

    return redirect(admin_settings.LOGIN_REDIRECT_URL)
