"""Minimal URLconf used only by tests exercising django_keycloak_jwt.admin_login
views/admin_site, which need reversible `keycloak_admin_login:*` URL names.
"""

from __future__ import annotations

from django.urls import include, path

urlpatterns = [
    path("admin-login/", include("django_keycloak_jwt.admin_login.urls")),
]
