from __future__ import annotations

import time

import pytest
import requests

from .conftest import TOKEN_URL, TokenGetter

pytestmark = [pytest.mark.e2e, pytest.mark.django_db(transaction=True)]


def test_public_endpoint_requires_no_token(live_server) -> None:
    response = requests.get(f"{live_server.url}/api/public/", timeout=10)
    assert response.status_code == 200


def test_no_token_is_401_with_www_authenticate(live_server) -> None:
    response = requests.get(f"{live_server.url}/api/me/", timeout=10)
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_alice_me(live_server, alice_token: str) -> None:
    response = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {alice_token}"},
        timeout=10,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice"
    assert body["realm_roles"] == ["staff"]
    # Alice also carries the admin_login e2e roles (django-admin-staff/
    # -superuser) on the same "api" client, since ROLE_CLIENT is shared
    # between the notes API and USER_MODEL_ROLE_FIELD_MAP in this realm.
    assert sorted(body["client_roles"]) == [
        "django-admin-staff",
        "django-admin-superuser",
        "editor",
        "reader",
    ]


def test_alice_creates_note_and_bob_cannot_see_it(
    live_server, alice_token: str, bob_token: str
) -> None:
    create = requests.post(
        f"{live_server.url}/api/notes/",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"text": "alice's note"},
        timeout=10,
    )
    assert create.status_code == 201
    note = create.json()
    assert note["text"] == "alice's note"

    alice_list = requests.get(
        f"{live_server.url}/api/notes/",
        headers={"Authorization": f"Bearer {alice_token}"},
        timeout=10,
    )
    assert any(n["id"] == note["id"] for n in alice_list.json())

    bob_list = requests.get(
        f"{live_server.url}/api/notes/",
        headers={"Authorization": f"Bearer {bob_token}"},
        timeout=10,
    )
    assert all(n["id"] != note["id"] for n in bob_list.json())


def test_bob_cannot_create_note(live_server, bob_token: str) -> None:
    response = requests.post(
        f"{live_server.url}/api/notes/",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"text": "nope"},
        timeout=10,
    )
    assert response.status_code == 403


def test_staff_role(live_server, alice_token: str, bob_token: str) -> None:
    alice_resp = requests.get(
        f"{live_server.url}/api/staff/",
        headers={"Authorization": f"Bearer {alice_token}"},
        timeout=10,
    )
    assert alice_resp.status_code == 200

    bob_resp = requests.get(
        f"{live_server.url}/api/staff/",
        headers={"Authorization": f"Bearer {bob_token}"},
        timeout=10,
    )
    assert bob_resp.status_code == 403


def test_token_from_other_client_is_rejected(live_server, get_token: TokenGetter) -> None:
    token = get_token("other-client", "alice", "alice-pass")
    response = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert response.status_code == 401


def test_refresh_token_as_bearer_is_rejected(live_server) -> None:
    data = {
        "grant_type": "password",
        "client_id": "frontend",
        "username": "alice",
        "password": "alice-pass",
        "scope": "openid",
    }
    token_response = requests.post(TOKEN_URL, data=data, timeout=10)
    token_response.raise_for_status()
    refresh_token = token_response.json()["refresh_token"]

    response = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {refresh_token}"},
        timeout=10,
    )
    assert response.status_code == 401


def test_id_token_as_bearer_is_rejected(live_server) -> None:
    data = {
        "grant_type": "password",
        "client_id": "frontend",
        "username": "alice",
        "password": "alice-pass",
        "scope": "openid",
    }
    token_response = requests.post(TOKEN_URL, data=data, timeout=10)
    token_response.raise_for_status()
    id_token = token_response.json()["id_token"]

    response = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {id_token}"},
        timeout=10,
    )
    assert response.status_code == 401


def test_tampered_token_is_rejected(live_server, alice_token: str) -> None:
    header, payload, signature = alice_token.split(".")
    # Flip a character in the middle of the signature, not the last one or
    # two: base64url's final partial group can have "don't care" bits that
    # decode to the same byte, making the tamper a no-op.
    middle = len(signature) // 2
    flipped_char = "A" if signature[middle] != "A" else "B"
    flipped = signature[:middle] + flipped_char + signature[middle + 1 :]
    tampered = f"{header}.{payload}.{flipped}"

    response = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=10,
    )
    assert response.status_code == 401


def test_frontend_short_expires(live_server, get_token: TokenGetter) -> None:
    token = get_token("frontend-short", "alice", "alice-pass")

    immediate = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert immediate.status_code == 200

    time.sleep(7)

    expired = requests.get(
        f"{live_server.url}/api/me/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert expired.status_code == 401
    assert expired.json()["detail"] == "token_expired"
