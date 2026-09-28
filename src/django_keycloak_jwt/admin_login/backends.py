"""Authentication backend required by ``django.contrib.auth.login``.

The actual authentication happens in ``views.callback`` by validating a
Keycloak ID token directly -- this backend exists only so Django has a
dotted path to stamp onto the session (``login()`` requires one) and so
``ModelBackend.get_user`` can reload the user on later requests.
``authenticate()`` always returns ``None``: this backend is never used to
authenticate a request from scratch.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib.auth.backends import ModelBackend

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.http import HttpRequest

BACKEND_PATH = "django_keycloak_jwt.admin_login.backends.KeycloakAdminBackend"


class KeycloakAdminBackend(ModelBackend):
    # django-stubs types ModelBackend.authenticate against the concrete
    # auth.User model; this deliberately supports any AUTH_USER_MODEL.
    def authenticate(  # type: ignore[override]
        self, request: HttpRequest | None, **kwargs: Any
    ) -> AbstractBaseUser | None:
        return None
