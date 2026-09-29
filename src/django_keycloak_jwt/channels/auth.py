"""Token extraction from the WebSocket handshake, and async authentication.

The browser WebSocket API can't set an ``Authorization`` header on the
handshake, so the token travels as the second entry of the client's offered
``Sec-WebSocket-Protocol`` list instead::

    new WebSocket(url, ["access_token", token])

This never touches the URL or query string (so it doesn't end up in
server/proxy access logs), at the cost of the server needing to echo back
the chosen subprotocol on ``accept()`` -- see
:mod:`django_keycloak_jwt.channels.consumer`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from asgiref.sync import sync_to_async
from channels.db import database_sync_to_async
from django.utils.module_loading import import_string

from .. import validation
from ..conf import get_settings
from ..user_resolution import resolve_user
from .conf import get_channels_settings

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser

    from ..principal import KeycloakUser

#: Length of the ``[marker, token]`` subprotocol pair.
_SUBPROTOCOL_PAIR_LENGTH = 2


def extract_token(scope: dict[str, Any]) -> str | None:
    """Return the bearer token offered via ``Sec-WebSocket-Protocol``, or ``None``.

    ``None`` means no token was offered at all -- the caller should treat
    the connection as anonymous rather than reject it, mirroring
    ``KeycloakJWTAuthentication`` returning ``None`` for a missing header.
    """
    subprotocols = scope.get("subprotocols") or []
    marker = get_channels_settings().SUBPROTOCOL_NAME
    if len(subprotocols) >= _SUBPROTOCOL_PAIR_LENGTH and subprotocols[0] == marker:
        return str(subprotocols[1])
    return None


async def authenticate(token: str) -> tuple[KeycloakUser | AbstractBaseUser, float]:
    """Validate *token* and return ``(user, expiry)``.

    ``user`` is a ``KeycloakUser`` (or ``USER_CLASS``), or the resolved
    ``AUTH_USER_MODEL`` instance if ``USER_MODEL_ENABLED``. ``expiry`` is
    the token's ``exp`` claim adjusted by ``LEEWAY``, matching how
    :func:`django_keycloak_jwt.validation.validate_token` already tolerates
    that many seconds past ``exp``.

    Raises the same exceptions as ``validate_token``/``resolve_user``:
    :class:`~django_keycloak_jwt.exceptions.TokenInvalid`,
    :class:`~django_keycloak_jwt.exceptions.TokenExpired`,
    :class:`~django_keycloak_jwt.exceptions.KeysUnavailable`, and
    :class:`~django_keycloak_jwt.exceptions.UserNotFound`.
    """
    # No DB access here, so a plain (non-thread-sensitive) thread is fine --
    # thread_sensitive=True would otherwise funnel this through the same
    # single thread reserved for ORM calls, for no benefit.
    claims = await sync_to_async(validation.validate_token, thread_sensitive=False)(token)

    settings = get_settings()
    if settings.USER_MODEL_ENABLED:
        user = await database_sync_to_async(resolve_user)(claims)
    else:
        principal_class = import_string(settings.USER_CLASS)
        user = principal_class(claims)

    expiry = float(claims["exp"]) + settings.LEEWAY
    return user, expiry
