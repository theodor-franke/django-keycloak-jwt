"""An ``AdminSite`` whose login view redirects into the Keycloak OIDC flow.

Usage, in your project (before any ``@admin.register`` calls run, e.g. at
the top of ``urls.py``)::

    from django.contrib import admin
    from django_keycloak_jwt.admin_login.admin_site import KeycloakAdminSite

    admin.site.__class__ = KeycloakAdminSite

Swapping the class in place (rather than constructing a separate
``AdminSite`` instance) means every app's existing ``admin.site.register(...)``
calls -- including ``django.contrib.auth``'s own ``User``/``Group`` admin --
keep working against the same site, unmodified.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.admin import AdminSite
from django.http import HttpResponseRedirect
from django.urls import reverse

if TYPE_CHECKING:
    from django.http import HttpRequest


class KeycloakAdminSite(AdminSite):
    def login(
        self, request: HttpRequest, extra_context: dict[str, object] | None = None
    ) -> HttpResponseRedirect:
        next_url = request.GET.get("next", request.path)
        login_url = reverse("keycloak_admin_login:login")
        return HttpResponseRedirect(f"{login_url}?next={next_url}")
