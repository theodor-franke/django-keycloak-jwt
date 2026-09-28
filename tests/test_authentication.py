from __future__ import annotations

import time

import pytest
from django.contrib.auth.models import User
from django.test import override_settings
from rest_framework.test import APIRequestFactory

from django_keycloak_jwt.drf.authentication import KeycloakJWTAuthentication

from .conftest import AUDIENCE, ISSUER, JWKSServer, Signer, TokenFactory
from .views import EchoUserView

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


def test_valid_token_authenticates_and_populates_request_user(
    make_token: TokenFactory,
) -> None:
    token = make_token()
    request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = EchoUserView.as_view()(request)

    assert response.status_code == 200
    assert response.data["authenticated"] is True
    assert response.data["sub"] == "11111111-1111-1111-1111-111111111111"
    assert response.data["username"] == "alice"


@pytest.mark.django_db
def test_authentication_makes_zero_db_queries(
    make_token: TokenFactory, django_assert_num_queries
) -> None:
    token = make_token()
    request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with django_assert_num_queries(0):
        response = EchoUserView.as_view()(request)

    assert response.status_code == 200


def test_no_header_is_anonymous() -> None:
    request = factory.get("/echo/")
    response = EchoUserView.as_view()(request)

    assert response.status_code == 200
    assert response.data["authenticated"] is False


@pytest.mark.parametrize("header", ["Token abc", "Basic dXNlcjpwYXNz"])
def test_other_auth_schemes_are_ignored(header: str) -> None:
    request = factory.get("/echo/", HTTP_AUTHORIZATION=header)
    response = EchoUserView.as_view()(request)

    assert response.status_code == 200
    assert response.data["authenticated"] is False


def test_bearer_without_token_is_401() -> None:
    request = factory.get("/echo/", HTTP_AUTHORIZATION="Bearer")
    response = EchoUserView.as_view()(request)
    assert response.status_code == 401


def test_bearer_with_extra_parts_is_401() -> None:
    request = factory.get("/echo/", HTTP_AUTHORIZATION="Bearer a b")
    response = EchoUserView.as_view()(request)
    assert response.status_code == 401


def test_expired_token_is_401_with_code(make_token: TokenFactory) -> None:
    now = int(time.time())
    token = make_token(claims={"iat": now - 1000, "exp": now - 100})
    request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = EchoUserView.as_view()(request)

    assert response.status_code == 401
    assert response.data["detail"].code == "token_expired"


def test_invalid_token_is_401_with_code(make_token: TokenFactory) -> None:
    token = make_token(claims={"iss": "https://evil.example/realms/test"})
    request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = EchoUserView.as_view()(request)

    assert response.status_code == 401
    assert response.data["detail"].code == "token_not_valid"


def test_keys_unavailable_is_503(make_token: TokenFactory, jwks_server: JWKSServer) -> None:
    jwks_server.state.status_code = 500
    token = make_token()
    request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = EchoUserView.as_view()(request)

    assert response.status_code == 503
    assert response.data["detail"].code == "auth_unavailable"


def test_www_authenticate_header_present_on_401(make_token: TokenFactory) -> None:
    token = make_token(claims={"iss": "https://evil.example/realms/test"})
    request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
    response = EchoUserView.as_view()(request)

    assert response.status_code == 401
    assert response["WWW-Authenticate"] == 'Bearer realm="api"'


@pytest.mark.django_db
def test_user_model_enabled_returns_resolved_db_user(
    make_token: TokenFactory, jwks_server: JWKSServer, signer: Signer
) -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "JWKS_URL": jwks_server.url,
            "ROLE_CLIENT": "api",
            "USER_MODEL_ENABLED": True,
            "USER_MODEL_LOOKUP_CLAIM": "sub",
            "USER_MODEL_LOOKUP_FIELD": "username",
            "USER_MODEL_FIELD_MAP": {"email": "email"},
        }
    ):
        jwks_server.set_keys(signer.jwk)
        token = make_token(claims={"sub": "alice-sub"})
        request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
        result = KeycloakJWTAuthentication().authenticate(request)

    assert result is not None
    user, raw_token = result
    assert raw_token == token
    assert user.username == "alice-sub"
    assert user.keycloak.sub == "alice-sub"
    assert User.objects.filter(username="alice-sub").exists()


@pytest.mark.django_db
def test_user_model_enabled_auto_create_false_is_401(
    make_token: TokenFactory, jwks_server: JWKSServer, signer: Signer
) -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "JWKS_URL": jwks_server.url,
            "ROLE_CLIENT": "api",
            "USER_MODEL_ENABLED": True,
            "USER_MODEL_LOOKUP_CLAIM": "sub",
            "USER_MODEL_LOOKUP_FIELD": "username",
            "USER_MODEL_FIELD_MAP": {"email": "email"},
            "USER_MODEL_AUTO_CREATE": False,
        }
    ):
        jwks_server.set_keys(signer.jwk)
        token = make_token(claims={"sub": "no-such-user"})
        request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = EchoUserView.as_view()(request)

    assert response.status_code == 401
    assert response.data["detail"].code == "user_not_provisioned"


def test_no_raw_token_in_logs(make_token: TokenFactory, caplog: pytest.LogCaptureFixture) -> None:
    token = make_token()
    with caplog.at_level("DEBUG"):
        request = factory.get("/echo/", HTTP_AUTHORIZATION=f"Bearer {token}")
        EchoUserView.as_view()(request)

    for record in caplog.records:
        assert token not in record.getMessage()
