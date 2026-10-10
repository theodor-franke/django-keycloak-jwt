"""Django settings for the django_keycloak_jwt example/e2e project.

Enables every optional feature the package offers: the DRF resource-server
path *and* cached ``AUTH_USER_MODEL`` resolution (``USER_MODEL_*``) *and*
the Keycloak OIDC login flow for Django admin (``admin_login``). A project
that only wants the stateless resource-server behavior would drop
``USER_MODEL_ENABLED``, ``django_keycloak_jwt.admin_login``, and the
session/admin apps/middleware below.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "example-project-dev-secret-not-for-production")
DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() == "true"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "rest_framework",
    "django_keycloak_jwt",
    "django_keycloak_jwt.admin_login",
    "accounts",
    "notes",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django_keycloak_jwt.admin_login.middleware.KeycloakAdminSessionMiddleware",
    # Self-gating (no-op unless KEYCLOAK_JWT_ADMIN['COOKIE_MODE'] is True), so
    # it's safe to carry here even though the example project defaults to
    # session mode -- e2e tests flip COOKIE_MODE on per-test via
    # override_settings to exercise it against this same live server.
    "django_keycloak_jwt.admin_login.cookie_middleware.KeycloakAdminCookieMiddleware",
]

AUTH_USER_MODEL = "accounts.User"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_keycloak_jwt.admin_login.backends.KeycloakAdminBackend",
]

ROOT_URLCONF = "example_project.urls"
WSGI_APPLICATION = "example_project.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "NAME": os.environ.get("POSTGRES_DB", "keycloak_jwt_example"),
        "USER": os.environ.get("POSTGRES_USER", "keycloak_jwt"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "keycloak_jwt"),
    }
}

# LocMemCache for the demo; USER_MODEL_ENABLED requires a process-shared
# backend (Redis/Memcached) in any multi-worker deployment so that cache
# invalidation on user-model changes is visible across workers -- see
# django_keycloak_jwt.W003. Expect that check to fire here; it's accurate.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

USE_TZ = True

STATIC_URL = "/static/"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_keycloak_jwt.drf.authentication.KeycloakJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

KEYCLOAK_JWT = {
    "ISSUER": os.environ.get("KC_ISSUER", "http://localhost:8080/realms/test"),
    "AUDIENCE": os.environ.get("KC_AUDIENCE", "api"),
    "ROLE_CLIENT": os.environ.get("KC_ROLE_CLIENT", "api"),
    "LEEWAY": int(os.environ.get("KEYCLOAK_JWT_LEEWAY", "0")),
    "USER_MODEL_ENABLED": True,
    "USER_MODEL_LOOKUP_CLAIM": "sub",
    "USER_MODEL_LOOKUP_FIELD": "keycloak_sub",
    "USER_MODEL_AUTO_CREATE": True,
    "USER_MODEL_CACHE_TTL": int(os.environ.get("KEYCLOAK_JWT_USER_MODEL_CACHE_TTL", "300")),
    # Client roles (on ROLE_CLIENT, "api") that grant Django admin access --
    # required to be non-empty by django_keycloak_jwt.admin_login.E004.
    "USER_MODEL_ROLE_FIELD_MAP": {
        "django-admin-staff": "is_staff",
        "django-admin-superuser": "is_superuser",
    },
}

KEYCLOAK_JWT_ADMIN = {
    "CLIENT_ID": os.environ.get("KC_ADMIN_CLIENT_ID", "django-admin"),
    "LOGOUT_END_SESSION": True,
}
