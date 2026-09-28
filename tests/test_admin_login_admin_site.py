from __future__ import annotations

from django.test import RequestFactory, override_settings

from django_keycloak_jwt.admin_login.admin_site import KeycloakAdminSite

factory = RequestFactory()


@override_settings(ROOT_URLCONF="tests.admin_login_urls")
def test_login_redirects_to_keycloak_login_view() -> None:
    request = factory.get("/admin/", {"next": "/admin/notes/"})
    response = KeycloakAdminSite().login(request)

    assert response.status_code == 302
    assert response.url.startswith("/admin-login/login/")
    assert "next=%2Fadmin%2Fnotes%2F" in response.url or "next=/admin/notes/" in response.url


@override_settings(ROOT_URLCONF="tests.admin_login_urls")
def test_login_defaults_next_to_request_path() -> None:
    request = factory.get("/admin/notes/note/")
    response = KeycloakAdminSite().login(request)

    assert "/admin/notes/note/" in response.url
