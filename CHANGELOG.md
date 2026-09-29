# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-09-29

### Added

- `KEYCLOAK_JWT['USER_MODEL_ENABLED']` — opt-in resolution of a real `AUTH_USER_MODEL`
  row from verified claims (`django_keycloak_jwt.user_resolution.resolve_user`),
  cached in Django's default cache (`USER_MODEL_CACHE_TTL`, default 300s) and
  invalidated via `post_save`/`post_delete` signals on the user model. Configurable
  claim/field matching (`USER_MODEL_LOOKUP_CLAIM`/`USER_MODEL_LOOKUP_FIELD`), a
  claim→field sync map (`USER_MODEL_FIELD_MAP`), auto-provisioning
  (`USER_MODEL_AUTO_CREATE`), and a client-role→boolean-field sync map
  (`USER_MODEL_ROLE_FIELD_MAP`, e.g. for `is_staff`/`is_superuser`). Disabled by
  default — the authentication path is unchanged unless this is turned on.
- `django_keycloak_jwt.admin_login` — a separate, opt-in Django app implementing a
  Keycloak OIDC (Authorization Code + PKCE, public client, no secret) login flow for
  Django admin: `KeycloakAdminSite` (drop-in replacement login view),
  `KeycloakAdminBackend`, `KeycloakAdminSessionMiddleware` (silent session renewal via
  refresh token), and login/callback/logout views gated on `USER_MODEL_ROLE_FIELD_MAP`.
  Built entirely on top of `USER_MODEL_ENABLED`; installs and affects nothing for
  projects that don't add it.
- `django_keycloak_jwt.discovery` — lazy, cached OIDC discovery document fetching
  (`.well-known/openid-configuration`), used by `admin_login` to resolve Keycloak's
  authorization/token/end-session endpoints without hand-configuring them.
- New system checks: `E004`/`E005` (core) for `USER_MODEL_*` misconfiguration and a
  lookup-field/field-map collision guard; `W003` warning when `USER_MODEL_ENABLED` is
  paired with the per-process `LocMemCache`; `admin_login.E001`–`E004`/`W001`–`W002`
  for `KEYCLOAK_JWT_ADMIN` misconfiguration, including refusing to start with an empty
  `USER_MODEL_ROLE_FIELD_MAP`.
- `example_project` now enables every optional feature end-to-end: a custom
  `accounts.User` model (`keycloak_sub` field), Django admin wired through
  `admin_login`, and the corresponding Keycloak client/roles in
  `e2e/keycloak/realm-test.json`.
- `django_keycloak_jwt.channels` — a separate, opt-in Django Channels integration
  (`pip install "django-keycloak-jwt[channels]"`) authenticating WebSocket
  connections: `KeycloakChannelsAuthMiddleware` (token via the
  `Sec-WebSocket-Protocol` handshake, not the query string) and
  `KeycloakWebsocketConsumerMixin` (echoes the subprotocol on accept; schedules a
  disconnect at the token's `exp`, since a long-lived socket would otherwise
  outlive it unlike a per-request HTTP check). Reuses the framework-agnostic
  `validation.py` core via `sync_to_async`/`channels.db.database_sync_to_async`.
  New `KEYCLOAK_JWT_CHANNELS` settings (`SUBPROTOCOL_NAME`, three `CLOSE_CODE_*`
  keys, all defaulted) with their own system checks
  (`django_keycloak_jwt.channels.E001`/`E002`/`W001`/`W002`).

### Changed

- `HasRealmRole`/`HasClientRole` now also accept a resolved `AUTH_USER_MODEL`
  instance exposing the claims principal via `.keycloak`, not only a bare
  `KeycloakUser`, so they keep working whether or not `USER_MODEL_ENABLED` is on.
- `KeycloakJWTConfig.ready()` now only connects the `USER_MODEL_ENABLED`
  cache-invalidation signals if the setting is already `True` at Django startup,
  rather than unconditionally — zero signal-registration cost for projects that
  never enable the feature. Because of this, tests that exercise
  signal-triggered invalidation need `USER_MODEL_ENABLED` to be true from
  process start (not toggled via `override_settings` mid-session); they now live
  in a separate `tests_user_model/` suite with its own settings module, run via
  `make test-user-model`.

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
