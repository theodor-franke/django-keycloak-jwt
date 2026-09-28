from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from django_keycloak_jwt.discovery import get_discovery_document, reset_discovery_cache
from django_keycloak_jwt.exceptions import DiscoveryUnavailable


class _Handler(BaseHTTPRequestHandler):
    body = b'{"authorization_endpoint": "https://kc/auth"}'
    status = 200

    def do_GET(self) -> None:
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.status < 400:
            self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def discovery_server() -> Iterator[HTTPServer]:
    _Handler.body = b'{"authorization_endpoint": "https://kc/auth"}'
    _Handler.status = 200
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        reset_discovery_cache()


def _issuer(server: HTTPServer) -> str:
    port = server.server_address[1]
    return f"http://127.0.0.1:{port}"


def test_fetches_and_caches(discovery_server: HTTPServer) -> None:
    issuer = _issuer(discovery_server)
    document = get_discovery_document(issuer)
    assert document["authorization_endpoint"] == "https://kc/auth"

    # Second call is served from cache -- shut the server down and confirm
    # no new request is needed.
    discovery_server.shutdown()
    discovery_server.server_close()
    document_again = get_discovery_document(issuer)
    assert document_again == document


def test_unreachable_host_raises() -> None:
    with pytest.raises(DiscoveryUnavailable):
        get_discovery_document("http://127.0.0.1:1", timeout=1)


def test_malformed_json_raises(discovery_server: HTTPServer) -> None:
    _Handler.body = b"not json"
    issuer = _issuer(discovery_server)
    with pytest.raises(DiscoveryUnavailable, match="not valid JSON"):
        get_discovery_document(issuer)


def test_non_object_json_raises(discovery_server: HTTPServer) -> None:
    _Handler.body = b"[1, 2, 3]"
    issuer = _issuer(discovery_server)
    with pytest.raises(DiscoveryUnavailable, match="not a JSON object"):
        get_discovery_document(issuer)
