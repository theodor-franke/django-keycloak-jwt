from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from keycloak_jwt.conf import get_settings


def test_jwks_url_derived_from_issuer() -> None:
    settings = get_settings()
    assert f"{settings.ISSUER}/protocol/openid-connect/certs" == settings.JWKS_URL


def test_jwks_url_explicit_override_wins() -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "test-client",
            "JWKS_URL": "https://internal.example/certs",
        }
    ):
        assert get_settings().JWKS_URL == "https://internal.example/certs"


def test_audiences_normalizes_str_to_list() -> None:
    with override_settings(
        KEYCLOAK_JWT={"ISSUER": "https://kc.example.test/realms/test", "AUDIENCE": "one"}
    ):
        assert get_settings().audiences == ["one"]


def test_audiences_preserves_list() -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": ["one", "two"],
        }
    ):
        assert get_settings().audiences == ["one", "two"]


def test_missing_issuer_raises() -> None:
    with (
        override_settings(KEYCLOAK_JWT={"AUDIENCE": "test-client"}),
        pytest.raises(ImproperlyConfigured, match="ISSUER"),
    ):
        get_settings()


def test_missing_audience_raises() -> None:
    with (
        override_settings(KEYCLOAK_JWT={"ISSUER": "https://kc.example.test/realms/test"}),
        pytest.raises(ImproperlyConfigured, match="AUDIENCE"),
    ):
        get_settings()


def test_missing_setting_entirely_raises() -> None:
    with override_settings(KEYCLOAK_JWT=None), pytest.raises(ImproperlyConfigured):
        get_settings()


@pytest.mark.parametrize("bad_alg", ["none", "HS256", "HS384", "HS512"])
def test_forbidden_algorithm_raises(bad_alg: str) -> None:
    with (
        override_settings(
            KEYCLOAK_JWT={
                "ISSUER": "https://kc.example.test/realms/test",
                "AUDIENCE": "test-client",
                "ALGORITHMS": ["RS256", bad_alg],
            }
        ),
        pytest.raises(ImproperlyConfigured, match="forbidden"),
    ):
        get_settings()


def test_override_settings_invalidates_cache() -> None:
    with override_settings(KEYCLOAK_JWT={"ISSUER": "https://a.example/realms/a", "AUDIENCE": "a"}):
        assert get_settings().ISSUER == "https://a.example/realms/a"

    with override_settings(KEYCLOAK_JWT={"ISSUER": "https://b.example/realms/b", "AUDIENCE": "b"}):
        assert get_settings().ISSUER == "https://b.example/realms/b"

    assert get_settings().ISSUER == "https://kc.example.test/realms/test"
