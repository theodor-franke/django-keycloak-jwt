from __future__ import annotations

import base64
import json

import pytest
import requests

from .conftest import ADMIN_REALM_API, TokenGetter

pytestmark = [pytest.mark.e2e, pytest.mark.django_db(transaction=True)]


def _kid(token: str) -> str:
    header_b64 = token.split(".", maxsplit=1)[0]
    header_b64 += "=" * (-len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    return str(header["kid"])


def test_key_rotation_is_picked_up_without_restart(
    live_server,
    get_token: TokenGetter,
    admin_headers: dict[str, str],
    realm_internal_id: str,
) -> None:
    old_token = get_token("frontend", "alice", "alice-pass")
    old_kid = _kid(old_token)

    old_response = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {old_token}"},
        timeout=10,
    )
    assert old_response.status_code == 200

    component = {
        "name": "rsa-generated-rotated",
        "providerId": "rsa-generated",
        "providerType": "org.keycloak.keys.KeyProvider",
        "parentId": realm_internal_id,
        "config": {
            "priority": ["200"],
            "enabled": ["true"],
            "active": ["true"],
            "algorithm": ["RS256"],
        },
    }
    create = requests.post(
        f"{ADMIN_REALM_API}/components", json=component, headers=admin_headers, timeout=10
    )
    assert create.status_code == 201, create.text
    component_id = create.headers["Location"].rstrip("/").rsplit("/", 1)[-1]

    try:
        new_token = get_token("frontend", "alice", "alice-pass")
        new_kid = _kid(new_token)
        assert new_kid != old_kid

        new_response = requests.get(
            f"{live_server.url}/api/me/",
            headers={"Authorization": f"Bearer {new_token}"},
            timeout=10,
        )
        assert new_response.status_code == 200

        # The old key is still published (Keycloak keeps rotated-out keys
        # around), so the old token must still validate too.
        still_old_response = requests.get(
            f"{live_server.url}/api/me/",
            headers={"Authorization": f"Bearer {old_token}"},
            timeout=10,
        )
        assert still_old_response.status_code == 200
    finally:
        requests.delete(
            f"{ADMIN_REALM_API}/components/{component_id}", headers=admin_headers, timeout=10
        )
