from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.algorithms import RSAAlgorithm

from django_keycloak_jwt import jwks as jwks_module

ISSUER = "https://kc.example.test/realms/test"
AUDIENCE = "test-client"


@dataclass
class JWKSState:
    keys: list[dict[str, Any]] = field(default_factory=list)
    status_code: int = 200
    delay: float = 0.0
    request_count: int = 0
    last_user_agent: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class _JWKSHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.state = JWKSState()


class _Handler(BaseHTTPRequestHandler):
    server: _JWKSHTTPServer

    def do_GET(self) -> None:
        state = self.server.state
        with state.lock:
            state.request_count += 1
            state.last_user_agent = self.headers.get("User-Agent")
            status_code = state.status_code
            delay = state.delay
            body = json.dumps({"keys": state.keys}).encode()

        if delay:
            time.sleep(delay)

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if status_code < 400:
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


class JWKSServer:
    """A real local HTTP server serving a mutable JWKS document."""

    def __init__(self, server: _JWKSHTTPServer) -> None:
        self._server = server

    @property
    def url(self) -> str:
        port = self._server.server_address[1]
        return f"http://127.0.0.1:{port}/protocol/openid-connect/certs"

    @property
    def state(self) -> JWKSState:
        return self._server.state

    def set_keys(self, *jwks: dict[str, Any]) -> None:
        with self.state.lock:
            self.state.keys = list(jwks)

    def add_key(self, jwk: dict[str, Any]) -> None:
        with self.state.lock:
            self.state.keys.append(jwk)


@pytest.fixture
def jwks_server() -> Iterator[JWKSServer]:
    server = _JWKSHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield JWKSServer(server)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        jwks_module.reset_jwks_cache()


def make_rsa_keypair() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(
    private_key: RSAPrivateKey, kid: str, *, use: str | None = "sig", alg: str = "RS256"
) -> dict[str, Any]:
    jwk: dict[str, Any] = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk["kid"] = kid
    jwk["alg"] = alg
    if use is not None:
        jwk["use"] = use
    return jwk


@dataclass
class Signer:
    private_key: RSAPrivateKey
    kid: str

    @property
    def jwk(self) -> dict[str, Any]:
        return public_jwk(self.private_key, self.kid)


@pytest.fixture
def signer() -> Signer:
    return Signer(private_key=make_rsa_keypair(), kid="test-kid-1")


TokenFactory = Callable[..., str]


@pytest.fixture
def make_token(signer: Signer) -> TokenFactory:
    def _make_token(
        *,
        private_key: RSAPrivateKey | None = None,
        kid: str | None = None,
        alg: str = "RS256",
        claims: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        default_claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "11111111-1111-1111-1111-111111111111",
            "iat": now,
            "exp": now + 300,
            "typ": "Bearer",
            "azp": "frontend",
            "preferred_username": "alice",
            "email": "alice@example.test",
            "given_name": "Alice",
            "family_name": "Example",
            "realm_access": {"roles": ["staff"]},
            "resource_access": {"api": {"roles": ["editor", "reader"]}},
        }
        merged_claims = {**default_claims, **(claims or {})}
        merged_headers = {"kid": kid if kid is not None else signer.kid, **(headers or {})}
        key = private_key if private_key is not None else signer.private_key
        token = jwt.encode(merged_claims, key, algorithm=alg, headers=merged_headers)
        return token

    return _make_token
