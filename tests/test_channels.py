from __future__ import annotations

import time
from typing import Any

import pytest
from asgiref.sync import async_to_sync
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.testing import WebsocketCommunicator
from django.test import override_settings

from django_keycloak_jwt.channels.auth import extract_token
from django_keycloak_jwt.channels.consumer import KeycloakWebsocketConsumerMixin
from django_keycloak_jwt.channels.middleware import KeycloakChannelsAuthMiddleware

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory

MARKER = "access_token"

# Every real Channels consumer dispatch (including the initial
# "websocket.connect") calls Django's aclose_old_connections()
# unconditionally (channels.consumer.AsyncConsumer.dispatch), regardless of
# whether the consumer itself touches the DB -- so any test that drives a
# real WebsocketCommunicator needs DB access allowed.
pytestmark = pytest.mark.django_db


class _ScopeEchoConsumer(AsyncJsonWebsocketConsumer):
    """Bare consumer (no mixin) used to inspect what the middleware put in
    scope, in isolation from the consumer mixin's own behavior."""

    async def connect(self) -> None:
        await self.accept()
        user = self.scope["user"]
        await self.send_json(
            {
                "authenticated": bool(getattr(user, "is_authenticated", False)),
                "class": user.__class__.__name__,
                "keycloak_exp": self.scope.get("keycloak_exp"),
            }
        )


class _MixinConsumer(KeycloakWebsocketConsumerMixin, AsyncJsonWebsocketConsumer):
    async def receive_json(self, content: Any, **kwargs: Any) -> None:
        await self.send_json({"echo": content})


def _kc_settings(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ISSUER": ISSUER,
        "AUDIENCE": AUDIENCE,
        "ROLE_CLIENT": "api",
        "LEEWAY": 0,
    }
    base.update(overrides)
    return base


# --- auth.extract_token -------------------------------------------------


def test_extract_token_present() -> None:
    assert extract_token({"subprotocols": [MARKER, "abc.def.ghi"]}) == "abc.def.ghi"


def test_extract_token_absent() -> None:
    assert extract_token({"subprotocols": []}) is None
    assert extract_token({}) is None


def test_extract_token_wrong_marker() -> None:
    assert extract_token({"subprotocols": ["other", "abc.def.ghi"]}) is None


def test_extract_token_marker_without_token() -> None:
    assert extract_token({"subprotocols": [MARKER]}) is None


# --- middleware ----------------------------------------------------------


def test_non_websocket_scope_passes_through_untouched() -> None:
    async def _run() -> None:
        calls = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            calls.append(scope)

        middleware = KeycloakChannelsAuthMiddleware(inner)
        scope = {"type": "http"}
        await middleware(scope, None, None)

        assert calls == [scope]
        assert "user" not in scope

    async_to_sync(_run)()


def test_no_subprotocol_is_anonymous_passthrough(jwks_server: JWKSServer, signer: Signer) -> None:
    with override_settings(KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url)):
        jwks_server.set_keys(signer.jwk)
        async_to_sync(_assert_anonymous_passthrough)()


async def _assert_anonymous_passthrough() -> None:
    application = KeycloakChannelsAuthMiddleware(_ScopeEchoConsumer.as_asgi())
    communicator = WebsocketCommunicator(application, "/ws/")
    connected, _ = await communicator.connect()
    assert connected
    message = await communicator.receive_json_from()
    assert message["authenticated"] is False
    assert message["class"] == "AnonymousUser"
    await communicator.disconnect()


def test_valid_token_sets_scope_user(
    jwks_server: JWKSServer, signer: Signer, make_token: TokenFactory
) -> None:
    with override_settings(KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url)):
        jwks_server.set_keys(signer.jwk)
        token = make_token()
        async_to_sync(_assert_valid_token)(token)


async def _assert_valid_token(token: str) -> None:
    application = KeycloakChannelsAuthMiddleware(_ScopeEchoConsumer.as_asgi())
    communicator = WebsocketCommunicator(application, "/ws/", subprotocols=[MARKER, token])
    connected, _ = await communicator.connect()
    assert connected
    message = await communicator.receive_json_from()
    assert message["authenticated"] is True
    assert message["class"] == "KeycloakUser"
    assert message["keycloak_exp"] is not None
    await communicator.disconnect()


def test_invalid_token_is_denied(jwks_server: JWKSServer, signer: Signer) -> None:
    with override_settings(KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url)):
        jwks_server.set_keys(signer.jwk)
        async_to_sync(_assert_denied)("not-a-jwt", expected_code=4401)


def test_expired_token_is_denied(
    jwks_server: JWKSServer, signer: Signer, make_token: TokenFactory
) -> None:
    with override_settings(KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url)):
        jwks_server.set_keys(signer.jwk)
        now = int(time.time())
        token = make_token(claims={"iat": now - 1000, "exp": now - 100})
        async_to_sync(_assert_denied)(token, expected_code=4401)


def test_keys_unavailable_is_denied(jwks_server: JWKSServer, make_token: TokenFactory) -> None:
    jwks_server.state.status_code = 500
    with override_settings(KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url)):
        token = make_token()
        async_to_sync(_assert_denied)(token, expected_code=4503)


def test_user_not_provisioned_is_denied(
    jwks_server: JWKSServer, signer: Signer, make_token: TokenFactory
) -> None:
    with override_settings(
        KEYCLOAK_JWT=_kc_settings(
            JWKS_URL=jwks_server.url,
            USER_MODEL_ENABLED=True,
            USER_MODEL_LOOKUP_CLAIM="sub",
            USER_MODEL_LOOKUP_FIELD="username",
            USER_MODEL_FIELD_MAP={"email": "email"},
            USER_MODEL_AUTO_CREATE=False,
        )
    ):
        jwks_server.set_keys(signer.jwk)
        token = make_token(claims={"sub": "no-such-user"})
        async_to_sync(_assert_denied)(token, expected_code=4401)


async def _assert_denied(token: str, *, expected_code: int) -> None:
    application = KeycloakChannelsAuthMiddleware(_ScopeEchoConsumer.as_asgi())
    communicator = WebsocketCommunicator(application, "/ws/", subprotocols=[MARKER, token])
    connected, code = await communicator.connect()
    assert connected is False
    assert code == expected_code


# --- consumer mixin --------------------------------------------------------


def test_mixin_accepts_with_echoed_subprotocol(
    jwks_server: JWKSServer, signer: Signer, make_token: TokenFactory
) -> None:
    with override_settings(KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url)):
        jwks_server.set_keys(signer.jwk)
        token = make_token()
        async_to_sync(_assert_mixin_accepts)(token)


async def _assert_mixin_accepts(token: str) -> None:
    application = KeycloakChannelsAuthMiddleware(_MixinConsumer.as_asgi())
    communicator = WebsocketCommunicator(application, "/ws/", subprotocols=[MARKER, token])
    connected, subprotocol = await communicator.connect()
    assert connected
    assert subprotocol == MARKER

    await communicator.send_json_to({"hello": "world"})
    response = await communicator.receive_json_from()
    assert response == {"echo": {"hello": "world"}}

    await communicator.disconnect()


def test_mixin_schedules_disconnect_at_expiry(
    jwks_server: JWKSServer, signer: Signer, make_token: TokenFactory
) -> None:
    with override_settings(
        KEYCLOAK_JWT=_kc_settings(JWKS_URL=jwks_server.url),
        KEYCLOAK_JWT_CHANNELS={"CLOSE_CODE_TOKEN_EXPIRED": 4001},
    ):
        jwks_server.set_keys(signer.jwk)
        now = int(time.time())
        # Valid at connect time (exp is a couple seconds out -- enough
        # margin that int() truncation and validation overhead can't put it
        # in the past before the connection is even established), but short
        # enough to observe the mixin's scheduled disconnect within the test.
        token = make_token(claims={"iat": now, "exp": now + 2})
        async_to_sync(_assert_mixin_expires)(token)


async def _assert_mixin_expires(token: str) -> None:
    application = KeycloakChannelsAuthMiddleware(_MixinConsumer.as_asgi())
    communicator = WebsocketCommunicator(application, "/ws/", subprotocols=[MARKER, token])
    connected, _ = await communicator.connect()
    assert connected

    event = await communicator.receive_output(timeout=5)
    assert event["type"] == "websocket.close"
    assert event.get("code") == 4001

    await communicator.disconnect()
