"""ASGI middleware authenticating WebSocket connections against Keycloak.

Mirrors :class:`~django_keycloak_jwt.drf.authentication.KeycloakJWTAuthentication`'s
philosophy: no token offered at all -> anonymous, pass through (so a route
can still be public); a token *is* offered but invalid/expired/unusable ->
the connection is denied outright, before the consumer's ``connect()`` ever
runs -- the earliest point a WebSocket handshake can be refused, playing
the same role a 401/503 response would for the DRF path.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser

from ..exceptions import KeysUnavailable, TokenExpired, TokenInvalid, UserNotFound
from .auth import authenticate, extract_token
from .conf import get_channels_settings

ASGIApp = Callable[[dict[str, Any], Any, Any], Awaitable[None]]


class KeycloakChannelsAuthMiddleware:
    """Wrap an ASGI application, populating ``scope["user"]`` for websockets.

    ::

        application = ProtocolTypeRouter({
            "websocket": KeycloakChannelsAuthMiddleware(URLRouter(websocket_urlpatterns)),
        })

    Non-websocket scopes (e.g. ``http``, if this ends up wrapping more than
    the websocket branch) are passed through untouched.
    """

    def __init__(self, inner: ASGIApp) -> None:
        self.inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "websocket":
            await self.inner(scope, receive, send)
            return

        token = extract_token(scope)
        if token is None:
            new_scope = {**scope, "user": AnonymousUser()}
            await self.inner(new_scope, receive, send)
            return

        channels_settings = get_channels_settings()
        try:
            user, expiry = await authenticate(token)
        except (TokenInvalid, TokenExpired, UserNotFound) as exc:
            denier = _Denier(channels_settings.CLOSE_CODE_TOKEN_INVALID, _reason(exc))
            await denier(scope, receive, send)
            return
        except KeysUnavailable as exc:
            denier = _Denier(channels_settings.CLOSE_CODE_AUTH_UNAVAILABLE, _reason(exc))
            await denier(scope, receive, send)
            return

        new_scope = {**scope, "user": user, "keycloak_exp": expiry}
        await self.inner(new_scope, receive, send)


def _reason(exc: Exception) -> str:
    reason = getattr(exc, "reason", None)
    return str(reason) if reason else exc.__class__.__name__


class _Denier(AsyncWebsocketConsumer):  # type: ignore[misc]
    """Accepts the ASGI websocket lifecycle far enough to send a close frame
    with a specific code/reason, then stops -- the standard Channels pattern
    for denying a connection (see ``channels.security.websocket.WebsocketDenier``),
    parameterized with the code/reason we want instead of the fixed default.
    """

    def __init__(self, code: int, reason: str = "") -> None:
        super().__init__()
        self._code = code
        self._reason = reason

    async def connect(self) -> None:
        await self.close(code=self._code, reason=self._reason)
