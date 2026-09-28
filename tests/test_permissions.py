from __future__ import annotations

import pytest
from django.contrib.auth.models import AnonymousUser
from django.test import override_settings
from rest_framework.test import APIRequestFactory

from django_keycloak_jwt.drf.permissions import HasClientRole, HasRealmRole
from django_keycloak_jwt.principal import KeycloakUser

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory
from .views import (
    RequireClientEditorExplicitClientView,
    RequireClientEditorView,
    RequireRealmStaffView,
)

factory = APIRequestFactory()


@pytest.fixture(autouse=True)
def _kc_settings(jwks_server: JWKSServer, signer: Signer):
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "JWKS_URL": jwks_server.url,
            "ROLE_CLIENT": "api",
        }
    ):
        jwks_server.set_keys(signer.jwk)
        yield


def test_realm_role_granted(make_token: TokenFactory) -> None:
    token = make_token(claims={"realm_access": {"roles": ["staff"]}})
    request = factory.get("/staff/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = RequireRealmStaffView.as_view()(request)
    assert response.status_code == 200


def test_realm_role_denied(make_token: TokenFactory) -> None:
    token = make_token(claims={"realm_access": {"roles": ["nobody"]}})
    request = factory.get("/staff/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = RequireRealmStaffView.as_view()(request)
    assert response.status_code == 403


def test_client_role_default_client_granted(make_token: TokenFactory) -> None:
    token = make_token(claims={"resource_access": {"api": {"roles": ["editor"]}}})
    request = factory.get("/notes/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = RequireClientEditorView.as_view()(request)
    assert response.status_code == 200


def test_client_role_default_client_denied(make_token: TokenFactory) -> None:
    token = make_token(claims={"resource_access": {"api": {"roles": ["reader"]}}})
    request = factory.get("/notes/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = RequireClientEditorView.as_view()(request)
    assert response.status_code == 403


def test_client_role_explicit_client_granted(make_token: TokenFactory) -> None:
    token = make_token(claims={"resource_access": {"other-api": {"roles": ["editor"]}}})
    request = factory.get("/other/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = RequireClientEditorExplicitClientView.as_view()(request)
    assert response.status_code == 200


def test_client_role_explicit_client_ignores_default_client_roles(
    make_token: TokenFactory,
) -> None:
    # Has "editor" on the default ("api") client, but the view requires it
    # on "other-api" specifically.
    token = make_token(claims={"resource_access": {"api": {"roles": ["editor"]}}})
    request = factory.get("/other/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = RequireClientEditorExplicitClientView.as_view()(request)
    assert response.status_code == 403


def test_anonymous_user_denied() -> None:
    request = factory.get("/staff/")
    request.user = AnonymousUser()
    response = RequireRealmStaffView.as_view()(request)
    assert response.status_code in (401, 403)


class _ResolvedUserStub:
    """Stands in for a USER_MODEL_ENABLED-resolved AUTH_USER_MODEL instance."""

    def __init__(self, keycloak: KeycloakUser) -> None:
        self.keycloak = keycloak


def test_has_realm_role_accepts_keycloak_attribute() -> None:
    request = factory.get("/staff/")
    request.user = _ResolvedUserStub(KeycloakUser({"realm_access": {"roles": ["staff"]}}))

    assert HasRealmRole.of("staff")().has_permission(request, None) is True


def test_has_client_role_accepts_keycloak_attribute() -> None:
    request = factory.get("/notes/")
    request.user = _ResolvedUserStub(
        KeycloakUser({"resource_access": {"api": {"roles": ["editor"]}}})
    )

    assert HasClientRole.of("editor")().has_permission(request, None) is True


def test_has_realm_role_denied_without_keycloak_attribute() -> None:
    request = factory.get("/staff/")
    request.user = object()

    assert HasRealmRole.of("staff")().has_permission(request, None) is False
