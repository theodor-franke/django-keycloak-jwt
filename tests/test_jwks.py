from __future__ import annotations

import time

import pytest
from django.test import override_settings

from keycloak_jwt import jwks
from keycloak_jwt.conf import get_settings
from keycloak_jwt.exceptions import KeysUnavailable, TokenInvalid

from .conftest import JWKSServer, Signer, make_rsa_keypair, public_jwk


def _kc_settings(url: str, **overrides: object) -> object:
    payload = {
        "ISSUER": "https://kc.example.test/realms/test",
        "AUDIENCE": "test-client",
        "JWKS_URL": url,
        "JWKS_CACHE_LIFESPAN": 300,
        "JWKS_MIN_REFETCH_INTERVAL": 30,
        "HTTP_TIMEOUT": 2,
        **overrides,
    }
    with override_settings(KEYCLOAK_JWT=payload):
        return get_settings()


def test_resolves_known_key(jwks_server: JWKSServer, signer: Signer) -> None:
    jwks_server.set_keys(signer.jwk)
    settings = _kc_settings(jwks_server.url)

    key = jwks.get_signing_key(settings, signer.kid, "RS256")

    assert key.key_id == signer.kid
    assert key.algorithm_name == "RS256"


def test_sends_user_agent_header(jwks_server: JWKSServer, signer: Signer) -> None:
    jwks_server.set_keys(signer.jwk)
    settings = _kc_settings(jwks_server.url)

    jwks.get_signing_key(settings, signer.kid, "RS256")

    assert jwks_server.state.last_user_agent is not None
    assert "django-keycloak-jwt" in jwks_server.state.last_user_agent


def test_ignores_enc_keys(jwks_server: JWKSServer, signer: Signer) -> None:
    enc_key = public_jwk(make_rsa_keypair(), "enc-kid", use="enc")
    jwks_server.set_keys(enc_key, signer.jwk)
    settings = _kc_settings(jwks_server.url)

    with pytest.raises(TokenInvalid):
        jwks.get_signing_key(settings, "enc-kid", "RS256")

    key = jwks.get_signing_key(settings, signer.kid, "RS256")
    assert key.key_id == signer.kid


def test_unknown_kid_triggers_one_refetch_then_succeeds(
    jwks_server: JWKSServer, signer: Signer
) -> None:
    other = Signer(private_key=make_rsa_keypair(), kid="other-kid")
    jwks_server.set_keys(other.jwk)
    settings = _kc_settings(jwks_server.url, JWKS_MIN_REFETCH_INTERVAL=0)

    with pytest.raises(TokenInvalid):
        jwks.get_signing_key(settings, signer.kid, "RS256")
    assert jwks_server.state.request_count == 2  # initial fetch + one forced refetch

    # Simulate rotation: server now also serves the new key.
    jwks_server.add_key(signer.jwk)

    key = jwks.get_signing_key(settings, signer.kid, "RS256")
    assert key.key_id == signer.kid
    assert jwks_server.state.request_count == 3


def test_unknown_kid_spam_is_rate_limited(jwks_server: JWKSServer, signer: Signer) -> None:
    jwks_server.set_keys(signer.jwk)
    settings = _kc_settings(jwks_server.url, JWKS_MIN_REFETCH_INTERVAL=60)

    for _ in range(5):
        with pytest.raises(TokenInvalid):
            jwks.get_signing_key(settings, "totally-unknown-kid", "RS256")

    # One normal fetch + one forced refetch for the first unknown kid; every
    # subsequent attempt must be rejected without another network call.
    assert jwks_server.state.request_count == 2


def test_server_error_with_empty_cache_raises_keys_unavailable(
    jwks_server: JWKSServer, signer: Signer
) -> None:
    jwks_server.state.status_code = 500
    settings = _kc_settings(jwks_server.url)

    with pytest.raises(KeysUnavailable):
        jwks.get_signing_key(settings, signer.kid, "RS256")


def test_timeout_with_empty_cache_raises_keys_unavailable(
    jwks_server: JWKSServer, signer: Signer
) -> None:
    jwks_server.state.delay = 1.0
    settings = _kc_settings(jwks_server.url, HTTP_TIMEOUT=0.05)

    with pytest.raises(KeysUnavailable):
        jwks.get_signing_key(settings, signer.kid, "RS256")


def test_stale_key_used_when_server_down(
    jwks_server: JWKSServer, signer: Signer, caplog: pytest.LogCaptureFixture
) -> None:
    jwks_server.set_keys(signer.jwk)
    settings = _kc_settings(jwks_server.url, JWKS_CACHE_LIFESPAN=0.05)

    # Populate the "last known good" cache with a real successful fetch.
    key = jwks.get_signing_key(settings, signer.kid, "RS256")
    assert key.key_id == signer.kid

    time.sleep(0.1)  # let PyJWKClient's own TTL cache expire
    jwks_server.state.status_code = 500

    with caplog.at_level("WARNING", logger="keycloak_jwt"):
        key = jwks.get_signing_key(settings, signer.kid, "RS256")

    assert key.key_id == signer.kid
    assert any("stale" in record.message.lower() for record in caplog.records)


def test_reset_jwks_cache_clears_registry(jwks_server: JWKSServer, signer: Signer) -> None:
    jwks_server.set_keys(signer.jwk)
    settings = _kc_settings(jwks_server.url)
    jwks.get_signing_key(settings, signer.kid, "RS256")

    jwks.reset_jwks_cache()

    assert jwks._registry == {}
