"""Django settings for the "stateful" test suite.

Separate from ``tests/settings.py`` (and run as a separate pytest invocation,
see ``make test-user-model``) for one reason:
``KeycloakJWTConfig.ready()`` only connects the ``USER_MODEL_ENABLED``
cache-invalidation signals if the setting is already True at Django startup
-- it isn't re-evaluated on every request, so a test suite that flips it on
via ``override_settings`` mid-session (as ``tests/`` does) can exercise
``resolve_user`` directly but can never observe signal-triggered
invalidation. Here, ``USER_MODEL_ENABLED`` is True from the start, so the
signals are actually connected.
"""

from __future__ import annotations

SECRET_KEY = "test-secret-key-not-for-production"
DEBUG = True
USE_TZ = True
ALLOWED_HOSTS: list[str] = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "django_keycloak_jwt",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_keycloak_jwt.drf.authentication.KeycloakJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [],
}

KEYCLOAK_JWT = {
    "ISSUER": "https://kc.example.test/realms/test",
    "AUDIENCE": "test-client",
    "ROLE_CLIENT": "api",
    "LEEWAY": 10,
    "USER_MODEL_ENABLED": True,
    "USER_MODEL_LOOKUP_CLAIM": "sub",
    "USER_MODEL_LOOKUP_FIELD": "username",
    "USER_MODEL_FIELD_MAP": {
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
    },
    "USER_MODEL_AUTO_CREATE": True,
    "USER_MODEL_CACHE_TTL": 300,
    "USER_MODEL_ROLE_FIELD_MAP": {},
}
