"""PKCE, authorization-URL building, token-endpoint calls, and ID-token
validation for the admin OIDC login flow.

Deliberately uses a public client with PKCE (no client secret) even though
the code exchange happens server-side in ``views.py`` — PKCE's
``code_verifier`` already proves possession of the original request without
needing a secret, so there's nothing left for a secret to add here, only a
credential to manage.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

import jwt
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from .. import __version__
from ..conf import get_settings
from ..discovery import get_discovery_document
from ..exceptions import TokenExpired, TokenInvalid
from ..jwks import get_signing_key
from ..validation import REQUIRED_CLAIMS
from .conf import get_admin_settings
from .exceptions import TokenExchangeFailed

if TYPE_CHECKING:
    from .conf import KeycloakJWTAdminSettings

USER_AGENT = f"django-keycloak-jwt/{__version__}"


def generate_pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for the ``S256`` method."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def generate_state() -> str:
    """Return a random value for CSRF protection of the redirect flow."""
    return secrets.token_urlsafe(32)


def resolve_endpoints(issuer: str, admin_settings: KeycloakJWTAdminSettings) -> dict[str, str]:
    """Return the authorization/token/end-session endpoints to use.

    Explicit settings win; anything unset is filled in from the realm's
    OIDC discovery document (fetched lazily and cached, see
    :mod:`django_keycloak_jwt.discovery`).
    """
    needs_discovery = not (
        admin_settings.AUTHORIZATION_ENDPOINT
        and admin_settings.TOKEN_ENDPOINT
        and (admin_settings.END_SESSION_ENDPOINT or not admin_settings.LOGOUT_END_SESSION)
    )
    document: dict[str, Any] = {}
    if needs_discovery:
        document = get_discovery_document(issuer, timeout=admin_settings.HTTP_TIMEOUT)

    return {
        "authorization_endpoint": (
            admin_settings.AUTHORIZATION_ENDPOINT or document["authorization_endpoint"]
        ),
        "token_endpoint": admin_settings.TOKEN_ENDPOINT or document["token_endpoint"],
        "end_session_endpoint": (
            admin_settings.END_SESSION_ENDPOINT or document.get("end_session_endpoint", "")
        ),
    }


def build_authorization_url(
    *,
    endpoints: dict[str, str],
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{endpoints['authorization_endpoint']}?{urllib.parse.urlencode(params)}"


def exchange_code(
    *,
    endpoints: dict[str, str],
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    timeout: int,
) -> dict[str, Any]:
    return _post_form(
        endpoints["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": code_verifier,
        },
        timeout,
    )


def refresh_tokens(
    *, endpoints: dict[str, str], client_id: str, refresh_token: str, timeout: int
) -> dict[str, Any]:
    return _post_form(
        endpoints["token_endpoint"],
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        },
        timeout,
    )


def _post_form(url: str, data: dict[str, str], timeout: int) -> dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("ascii")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        raise TokenExchangeFailed(f"token endpoint returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise TokenExchangeFailed(f"token endpoint unreachable: {exc}") from exc

    try:
        result = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise TokenExchangeFailed("token endpoint response is not valid JSON") from exc

    if not isinstance(result, dict):
        raise TokenExchangeFailed("token endpoint response is not a JSON object")
    return result


def validate_id_token(raw: str) -> dict[str, Any]:
    """Validate an ID token returned by the admin OIDC client.

    Reuses the core JWKS/signature machinery (:func:`django_keycloak_jwt.jwks.get_signing_key`)
    but checks ``aud``/``azp`` against the admin client -- not
    ``KEYCLOAK_JWT['AUDIENCE']``, which is the resource-server API's
    audience and generally a different client -- and requires ``typ ==
    "ID"`` rather than ``"Bearer"``. Kept separate from
    :func:`django_keycloak_jwt.validation.validate_token` rather than
    overloading it with per-caller audience/typ overrides.
    """
    kc_settings = get_settings()
    admin_settings = get_admin_settings()

    try:
        header = jwt.get_unverified_header(raw)
    except PyJWTError as exc:
        raise TokenInvalid("malformed_header") from exc

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in kc_settings.ALGORITHMS:
        raise TokenInvalid("algorithm_not_allowed")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenInvalid("missing_kid")

    signing_key = get_signing_key(kc_settings, kid, alg)

    try:
        claims = jwt.decode(
            raw,
            key=signing_key,
            algorithms=kc_settings.ALGORITHMS,
            audience=admin_settings.CLIENT_ID,
            issuer=kc_settings.ISSUER,
            leeway=kc_settings.LEEWAY,
            options={"require": REQUIRED_CLAIMS},
        )
    except ExpiredSignatureError as exc:
        raise TokenExpired() from exc
    except PyJWTError as exc:
        raise TokenInvalid(exc.__class__.__name__) from exc

    if claims.get("typ") != "ID":
        raise TokenInvalid("unexpected_typ")
    if claims.get("azp") not in (None, admin_settings.CLIENT_ID):
        raise TokenInvalid("azp_not_allowed")

    return dict(claims)
