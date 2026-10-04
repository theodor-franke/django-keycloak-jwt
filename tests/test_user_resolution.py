from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from django_keycloak_jwt.exceptions import TokenInvalid, UserNotFound
from django_keycloak_jwt.user_resolution import resolve_user

from .conftest import AUDIENCE, ISSUER

pytestmark = pytest.mark.django_db

CLAIMS: dict[str, Any] = {
    "sub": "alice-sub",
    "email": "alice@example.test",
    "given_name": "Alice",
    "family_name": "Example",
    "preferred_username": "alice",
    "resource_access": {"api": {"roles": ["editor"]}},
}


def _settings(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ISSUER": ISSUER,
        "AUDIENCE": AUDIENCE,
        "ROLE_CLIENT": "api",
        "USER_MODEL_ENABLED": True,
        "USER_MODEL_LOOKUP_CLAIM": "sub",
        # A dedicated lookup field, distinct from anything USER_MODEL_FIELD_MAP
        # writes to -- auth.User has no spare column, so username stands in,
        # and the default FIELD_MAP's preferred_username->username entry is
        # dropped to avoid the two colliding (see django_keycloak_jwt.E005).
        "USER_MODEL_LOOKUP_FIELD": "username",
        "USER_MODEL_FIELD_MAP": {
            "email": "email",
            "given_name": "first_name",
            "family_name": "last_name",
        },
    }
    base.update(overrides)
    return base


def test_resolve_user_auto_creates() -> None:
    with override_settings(KEYCLOAK_JWT=_settings()):
        user = resolve_user(CLAIMS)

    assert user.username == "alice-sub"
    assert user.email == "alice@example.test"
    assert user.first_name == "Alice"
    assert user.last_name == "Example"
    assert user.keycloak.sub == "alice-sub"
    assert User.objects.count() == 1


def test_resolve_user_caches_without_second_db_hit() -> None:
    with override_settings(KEYCLOAK_JWT=_settings()):
        resolve_user(CLAIMS)

        with CaptureQueriesContext(connection) as ctx:
            resolve_user(CLAIMS)

    assert len(ctx) == 0


def test_resolve_user_missing_lookup_claim_raises() -> None:
    with (
        override_settings(KEYCLOAK_JWT=_settings()),
        pytest.raises(TokenInvalid, match="missing_user_model_lookup_claim"),
    ):
        resolve_user({"email": "no-sub@example.test"})


def test_resolve_user_auto_create_false_raises_when_missing() -> None:
    with (
        override_settings(KEYCLOAK_JWT=_settings(USER_MODEL_AUTO_CREATE=False)),
        pytest.raises(UserNotFound),
    ):
        resolve_user(CLAIMS)


def test_resolve_user_auto_create_false_finds_existing_row() -> None:
    User.objects.create(username="alice-sub")
    with override_settings(KEYCLOAK_JWT=_settings(USER_MODEL_AUTO_CREATE=False)):
        user = resolve_user(CLAIMS)

    assert user.username == "alice-sub"
    assert user.email == "alice@example.test"  # field map still applied on update


def test_resolve_user_updates_field_map_on_existing_row() -> None:
    with override_settings(KEYCLOAK_JWT=_settings()):
        resolve_user(CLAIMS)
        cache.clear()  # force a cache miss so the second call re-reads the row
        updated_claims = {**CLAIMS, "email": "alice-new@example.test"}
        user = resolve_user(updated_claims)

    assert user.email == "alice-new@example.test"
    assert User.objects.get(username="alice-sub").email == "alice-new@example.test"


def test_resolve_user_syncs_role_field_map() -> None:
    role_settings = _settings(USER_MODEL_ROLE_FIELD_MAP={"editor": "is_staff"})
    with override_settings(KEYCLOAK_JWT=role_settings):
        user = resolve_user(CLAIMS)
        assert user.is_staff is True

        cache.clear()  # force a cache miss so the second call re-syncs roles
        no_role_claims = {**CLAIMS, "resource_access": {"api": {"roles": []}}}
        user = resolve_user(no_role_claims)

    assert user.is_staff is False
    assert User.objects.get(username="alice-sub").is_staff is False


def test_resolve_user_dedupes_colliding_username_on_create() -> None:
    """USER_MODEL_LOOKUP_FIELD (sub-backed) and the FIELD_MAP's username
    target are independent columns in real deployments (see
    example_project's dedicated ``keycloak_sub`` field). Two different
    Keycloak subjects sharing a preferred_username must not crash the
    login -- the second one gets a numeric suffix instead.
    """
    User.objects.create(username="alice", email="someone-else@example.test")

    collision_settings = _settings(
        USER_MODEL_LOOKUP_FIELD="email",
        USER_MODEL_FIELD_MAP={"preferred_username": "username"},
    )
    with override_settings(KEYCLOAK_JWT=collision_settings):
        user = resolve_user(CLAIMS)

    assert user.username == "alice_1"
    assert User.objects.count() == 2


def test_resolve_user_dedupes_colliding_username_multiple_times() -> None:
    User.objects.create(username="alice")
    User.objects.create(username="alice_1")

    collision_settings = _settings(
        USER_MODEL_LOOKUP_FIELD="email",
        USER_MODEL_FIELD_MAP={"preferred_username": "username"},
    )
    with override_settings(KEYCLOAK_JWT=collision_settings):
        user = resolve_user(CLAIMS)

    assert user.username == "alice_2"


def test_resolve_user_dedupes_colliding_username_on_update() -> None:
    """The collision can just as easily surface on an *existing* row: the
    lookup field already matched (e.g. ``sub``), but the field map's
    username target now collides with a different row because some other
    Keycloak subject grabbed that ``preferred_username`` in the meantime.
    Re-syncing must not crash the login either.
    """
    # Looked up by email == claims["sub"] ("alice-sub"), independent of the
    # username the field map is about to write.
    User.objects.create(username="someone", email="alice-sub")
    User.objects.create(username="alice", email="someone-else@example.test")

    collision_settings = _settings(
        USER_MODEL_LOOKUP_FIELD="email",
        USER_MODEL_FIELD_MAP={"preferred_username": "username"},
    )
    with override_settings(KEYCLOAK_JWT=collision_settings):
        user = resolve_user(CLAIMS)

    assert user.username == "alice_1"
    assert User.objects.count() == 2


def test_resolve_user_stale_cache_is_not_invalidated_when_disabled_at_startup() -> None:
    """USER_MODEL_ENABLED is False at process startup under tests/settings.py,
    so KeycloakJWTConfig.ready() never connects the invalidation signals --
    even though this test enables the feature for its own duration, a save
    made through a *different* path (as here) leaves the cached copy stale.
    Signal-triggered invalidation is exercised for real in
    tests_user_model/test_cache_invalidation.py, under a settings module
    where USER_MODEL_ENABLED is already True at startup.
    """
    with override_settings(KEYCLOAK_JWT=_settings()):
        resolve_user(CLAIMS)
        user = User.objects.get(username="alice-sub")
        user.is_active = False
        user.save()  # would normally fire post_save -> invalidate_user_cache

        with CaptureQueriesContext(connection) as ctx:
            resolve_user(CLAIMS)

    assert len(ctx) == 0
