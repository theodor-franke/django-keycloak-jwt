"""Minimal Django settings for the django_keycloak_jwt example/e2e project.

Deliberately excludes ``django.contrib.sessions`` and its middleware: this
project is a pure OAuth2 resource server, it never creates sessions.
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
    "rest_framework",
    "django_keycloak_jwt",
    "notes",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
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

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

USE_TZ = True

# Unused by this API-only project, but required so that Django's test
# `live_server` fixture (which always wraps responses in a static-files
# handler) doesn't choke on urlparse(None) when STATIC_URL is unset.
STATIC_URL = "/static/"

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
}
