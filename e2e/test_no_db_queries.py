from __future__ import annotations

import pytest
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext

pytestmark = [pytest.mark.e2e, pytest.mark.django_db]


def test_authentication_path_makes_no_db_queries(alice_token: str) -> None:
    client = Client()

    # The example project has USER_MODEL_ENABLED on, so the *first* request
    # for a given user resolves (and caches) the local row -- that one DB
    # hit is expected. Warm the cache first, then assert steady-state
    # requests make none.
    client.get("/api/me/", HTTP_AUTHORIZATION=f"Bearer {alice_token}")

    with CaptureQueriesContext(connection) as ctx:
        response = client.get("/api/me/", HTTP_AUTHORIZATION=f"Bearer {alice_token}")

    assert response.status_code == 200
    assert len(ctx) == 0
