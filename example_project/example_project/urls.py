from django.contrib import admin
from django.urls import include, path

from django_keycloak_jwt.admin_login.admin_site import KeycloakAdminSite

# Swap in place so every app's existing admin.site.register(...) calls --
# including django.contrib.auth's own User/Group admin -- keep working
# against the same site, now with Keycloak-backed login.
admin.site.__class__ = KeycloakAdminSite

urlpatterns = [
    path("api/", include("notes.urls")),
    path("admin-login/", include("django_keycloak_jwt.admin_login.urls")),
    path("admin/", admin.site.urls),
]
