"""Tests that a saved/deleted AUTH_USER_MODEL row actually invalidates the
resolve_user() cache via the post_save/post_delete signals connected in
KeycloakJWTConfig.ready() -- which only happens because this suite's
settings module has USER_MODEL_ENABLED=True from process startup. See
tests_user_model/settings.py and `make test-user-model`.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth.models import User
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from django_keycloak_jwt.exceptions import UserNotFound
from django_keycloak_jwt.user_resolution import resolve_user

pytestmark = pytest.mark.django_db

CLAIMS: dict[str, Any] = {
    "sub": "alice-sub",
    "email": "alice@example.test",
    "given_name": "Alice",
    "family_name": "Example",
    "preferred_username": "alice",
    "resource_access": {"api": {"roles": ["editor"]}},
}


def test_cache_invalidated_on_user_save() -> None:
    resolve_user(CLAIMS)
    user = User.objects.get(username="alice-sub")
    user.is_active = False
    user.save()

    with CaptureQueriesContext(connection) as ctx:
        resolve_user(CLAIMS)

    assert len(ctx) > 0


def test_cache_survives_unrelated_process_state_between_calls() -> None:
    resolve_user(CLAIMS)

    with CaptureQueriesContext(connection) as ctx:
        resolve_user(CLAIMS)

    assert len(ctx) == 0


def test_cache_invalidated_on_user_delete() -> None:
    with override_settings(
        KEYCLOAK_JWT={
            "ISSUER": "https://kc.example.test/realms/test",
            "AUDIENCE": "test-client",
            "ROLE_CLIENT": "api",
            "USER_MODEL_ENABLED": True,
            "USER_MODEL_LOOKUP_CLAIM": "sub",
            "USER_MODEL_LOOKUP_FIELD": "username",
            "USER_MODEL_FIELD_MAP": {"email": "email"},
            "USER_MODEL_AUTO_CREATE": False,
        }
    ):
        User.objects.create(username="alice-sub")
        user = resolve_user(CLAIMS)
        assert user.username == "alice-sub"

        User.objects.get(username="alice-sub").delete()

        with pytest.raises(UserNotFound):
            resolve_user(CLAIMS)
