from __future__ import annotations

from django.urls import path

from . import views

app_name = "keycloak_admin_login"

urlpatterns = [
    path("login/", views.login, name="login"),
    path("callback/", views.callback, name="callback"),
    path("logout/", views.logout, name="logout"),
]
