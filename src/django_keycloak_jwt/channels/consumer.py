"""Handshake mechanics that pair with
:class:`~django_keycloak_jwt.channels.middleware.KeycloakChannelsAuthMiddleware`:
echoing back the subprotocol marker on accept (required by the WebSocket
spec once the client has offered any subprotocols at all) and closing the
connection when the token's ``exp`` arrives -- once validated at connect
time, a token is never re-checked for the rest of the connection otherwise.

For :class:`channels.generic.websocket.AsyncWebsocketConsumer` (or
``AsyncJsonWebsocketConsumer``) subclasses only -- the expiry disconnect is
an ``asyncio`` task, which needs a running event loop.

Auth is *not* enforced here: whether a consumer requires an authenticated
user is the consumer's call, same as ``IsAuthenticated`` is one permission
class among others for DRF views::

    class NotesConsumer(KeycloakWebsocketConsumerMixin, AsyncJsonWebsocketConsumer):
        async def connect(self):
            if not self.scope["user"].is_authenticated:
                await self.close(code=4401)
                return
            await super().connect()  # accepts + schedules the exp disconnect

        async def disconnect(self, code):
            await super().disconnect(code)  # cancels the pending expiry task
            ...
"""

from __future__ import annotations

import asyncio
import time

from channels.generic.websocket import AsyncWebsocketConsumer

from .conf import get_channels_settings


class KeycloakWebsocketConsumerMixin(AsyncWebsocketConsumer):  # type: ignore[misc]
    _keycloak_expiry_task: asyncio.Task[None] | None = None

    async def connect(self) -> None:
        channels_settings = get_channels_settings()
        await self.accept(subprotocol=channels_settings.SUBPROTOCOL_NAME)

        expiry = self.scope.get("keycloak_exp")
        if expiry is not None:
            self._keycloak_expiry_task = asyncio.create_task(self._keycloak_disconnect_at(expiry))

    async def disconnect(self, code: int) -> None:
        task = self._keycloak_expiry_task
        if task is not None:
            task.cancel()

    async def _keycloak_disconnect_at(self, expiry: float) -> None:
        delay = expiry - time.time()
        if delay > 0:
            await asyncio.sleep(delay)
        channels_settings = get_channels_settings()
        await self.close(code=channels_settings.CLOSE_CODE_TOKEN_EXPIRED)
