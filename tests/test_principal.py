from __future__ import annotations

import pytest
from django.test import override_settings

from django_keycloak_jwt.principal import KeycloakUser


def make_user(**claims: object) -> KeycloakUser:
    base = {"sub": "sub-123"}
    return KeycloakUser({**base, **claims})


def test_basic_fields() -> None:
    user = make_user(
        preferred_username="alice",
        email="alice@example.test",
        given_name="Alice",
        family_name="Example",
        azp="frontend",
    )
    assert user.sub == "sub-123"
    assert user.pk == "sub-123"
    assert user.id == "sub-123"
    assert user.username == "alice"
    assert user.email == "alice@example.test"
    assert user.given_name == "Alice"
    assert user.family_name == "Example"
    assert user.azp == "frontend"


def test_username_falls_back_to_sub() -> None:
    user = make_user()
    assert user.username == "sub-123"


def test_django_flags() -> None:
    user = make_user()
    assert user.is_authenticated is True
    assert user.is_anonymous is False
    assert user.is_active is True
    assert user.is_staff is False
    assert user.is_superuser is False


def test_permission_methods_always_false() -> None:
    user = make_user()
    assert user.has_perm("app.do_thing") is False
    assert user.has_perms(["app.do_thing"]) is False
    assert user.has_module_perms("app") is False


def test_realm_roles() -> None:
    user = make_user(realm_access={"roles": ["staff", "admin"]})
    assert user.realm_roles == frozenset({"staff", "admin"})
    assert user.has_realm_role("staff") is True
    assert user.has_realm_role("nope") is False


def test_realm_roles_missing_claim_is_empty() -> None:
    user = make_user()
    assert user.realm_roles == frozenset()


def test_client_roles_explicit_client() -> None:
    user = make_user(resource_access={"api": {"roles": ["editor"]}})
    assert user.client_roles("api") == frozenset({"editor"})
    assert user.has_client_role("editor", "api") is True
    assert user.has_client_role("reader", "api") is False


def test_client_roles_default_client_from_settings() -> None:
    user = make_user(resource_access={"api": {"roles": ["editor"]}})
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "x",
            "ROLE_CLIENT": "api",
        }
    ):
        assert user.client_roles() == frozenset({"editor"})


def test_client_roles_missing_claims_are_empty() -> None:
    user = make_user()
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "x",
            "ROLE_CLIENT": "api",
        }
    ):
        assert user.client_roles() == frozenset()
    assert user.client_roles("other-client") == frozenset()


def test_get_username_and_str() -> None:
    user = make_user(preferred_username="alice")
    assert user.get_username() == "alice"
    assert str(user) == "alice"


def test_equality_and_hash_by_sub() -> None:
    a = make_user(preferred_username="alice")
    b = KeycloakUser({"sub": "sub-123", "preferred_username": "someone-else"})
    c = make_user_with_sub("other-sub")
    assert a == b
    assert hash(a) == hash(b)
    assert a != c
    assert a != "not-a-user"


def make_user_with_sub(sub: str) -> KeycloakUser:
    return KeycloakUser({"sub": sub})


def test_claims_is_read_only_mapping() -> None:
    user = make_user()
    with pytest.raises(TypeError):
        user.claims["sub"] = "other"  # type: ignore[index]
