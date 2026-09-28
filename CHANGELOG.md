# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-09-28

### Added

- `KeycloakJWTAuthentication` — DRF authentication backend validating Keycloak-issued
  RS256 access tokens against the realm's JWKS. No sessions, no `auth.User` lookups,
  no database queries on the authentication path.
- Framework-agnostic validation core (`django_keycloak_jwt.validation`) usable outside DRF.
- Thread-safe JWKS cache (`django_keycloak_jwt.jwks`) with `kid`+`alg` key matching,
  rate-limited forced refetch on unknown `kid`, and stale-while-error fallback.
- `KeycloakUser` claims-backed principal with realm/client role helpers.
- `HasRealmRole` / `HasClientRole` DRF permission classes with `.of(...)` factories.
- Optional `drf-spectacular` `OpenApiAuthenticationExtension` integration.
- Django system checks for `KEYCLOAK_JWT` misconfiguration.
- `example_project/` demonstrating a minimal resource-server Django project against
  Postgres, and `e2e/keycloak/realm-test.json` — a Keycloak test realm covering
  audience mapping, role assignment, key rotation, and token expiry scenarios.
- Full unit and end-to-end test suites; CI running lint, unit (Python 3.13/3.14 ×
  Django 6.0/6.1), build, and e2e jobs.
