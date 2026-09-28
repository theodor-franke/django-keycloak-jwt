from __future__ import annotations

import pytest

pytest.importorskip("drf_spectacular")

from keycloak_jwt.drf.schema import KeycloakJWTScheme


def test_security_definition_is_bearer_jwt() -> None:
    scheme = KeycloakJWTScheme.__new__(KeycloakJWTScheme)
    definition = scheme.get_security_definition(auto_schema=None)

    assert definition == {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }


def test_target_class_points_at_authentication_backend() -> None:
    assert (
        KeycloakJWTScheme.target_class
        == "keycloak_jwt.drf.authentication.KeycloakJWTAuthentication"
    )
