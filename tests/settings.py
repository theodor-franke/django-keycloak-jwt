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
    "keycloak_jwt",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "keycloak_jwt.drf.authentication.KeycloakJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [],
}

KEYCLOAK_JWT = {
    "ISSUER": "https://kc.example.test/realms/test",
    "AUDIENCE": "test-client",
    "ROLE_CLIENT": "api",
    "LEEWAY": 10,
}
