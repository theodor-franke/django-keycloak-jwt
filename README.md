# django-keycloak-jwt

Stateless Keycloak JWT authentication for Django REST Framework.

By default, Django acts purely as an **OAuth2 resource server**: it validates
Keycloak-issued `RS256` access tokens on every request against Keycloak's published
JWKS. It never creates sessions, never stores users, and never calls Keycloak per
request beyond periodic JWKS refresh. Two things are opt-in on top of that default —
caching a resolved local user row ([Resolving a local user](#resolving-a-local-user-optional))
and a Keycloak OIDC login flow for Django admin
([Django admin login](#django-admin-login-optional)) — neither changes the default
behavior for anyone who doesn't enable them.

## What this is

- A DRF `BaseAuthentication` class that validates `Authorization: Bearer <token>`
  against a Keycloak realm's public keys.
- A claims-backed request principal (`request.user`) with realm/client role helpers.
- Permission classes for realm and client roles.
- A framework-agnostic validation core (`django_keycloak_jwt.validation`) with no Django or
  DRF imports, so it can be reused outside DRF (e.g. a future Django Channels
  middleware).
- Optionally: a cached `AUTH_USER_MODEL` resolution layer, and a separate
  `admin_login` module that lets Django admin be reached through Keycloak.

## What this is not

- **Not a login flow, by default.** There are no views for redirecting to Keycloak,
  handling the authorization code exchange, or logging users out unless you install
  the optional `admin_login` module (for the Django admin surface specifically).
  Token acquisition for the API is still entirely the frontend's job (Authorization
  Code + PKCE against Keycloak directly).
- **Not a user store, unless you opt in.** By default there is no `auth.User` row per
  Keycloak user, no signal that creates one on first login, no local profile table —
  the verified JWT claims *are* the user. Setting `USER_MODEL_ENABLED` trades that
  for a cached local row; see below.
- **Not a session system, for the API.** The DRF authentication path never uses
  `django.contrib.sessions` or a CSRF cookie, and revoking API access still means
  letting the (short-lived) token expire — see [Security notes](#security-notes).
  Django admin, once you opt into `admin_login`, is a normal server-rendered app and
  necessarily does use sessions — see [Django admin login](#django-admin-login-optional).
- **Not token introspection.** Tokens are verified locally via signature + claims;
  Keycloak is only contacted to fetch its public keys (JWKS) and, for `admin_login`,
  its OIDC discovery document — never per API request.

## Install

```bash
pip install django-keycloak-jwt
# or, for OpenAPI schema generation support:
pip install "django-keycloak-jwt[schema]"
```

Requires Python ≥ 3.13, Django 6.0/6.1, and `djangorestframework` ≥ 3.18.

Add to `INSTALLED_APPS` (registers the system checks in [Settings reference](#settings-reference)):

```python
INSTALLED_APPS = [
    ...,
    "rest_framework",
    "django_keycloak_jwt",
]
```

Wire up the authentication class, typically globally:

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_keycloak_jwt.drf.authentication.KeycloakJWTAuthentication",
    ],
}
```

## Settings reference

Configure a single `KEYCLOAK_JWT` dict in your Django settings:

```python
KEYCLOAK_JWT = {
    "ISSUER": "https://kc.example.com/realms/myrealm",
    "AUDIENCE": "my-backend",
    "ROLE_CLIENT": "my-backend",
}
```

| Key | Default | Notes |
|---|---|---|
| `ISSUER` | required | e.g. `https://kc.example.com/realms/myrealm`. Exact match against `iss`. |
| `AUDIENCE` | required | str or list. Token `aud` (str or list) must contain at least one. |
| `JWKS_URL` | `None` | If `None`, derived as `f"{ISSUER}/protocol/openid-connect/certs"`. Set explicitly if the internal URL differs from the public issuer. |
| `ALGORITHMS` | `["RS256"]` | Allowlist. `none` and any `HS*` are rejected even if configured (system check error). |
| `LEEWAY` | `10` | Seconds of clock-skew tolerance for `exp`/`nbf`/`iat`. |
| `ALLOWED_AZP` | `None` | Optional list of client IDs allowed as `azp`. |
| `REQUIRED_TYP` | `"Bearer"` | Keycloak sets `typ: Bearer` for access tokens, `ID` for ID tokens, `Refresh` for refresh tokens — only `Bearer` is accepted by default. |
| `ROLE_CLIENT` | `None` | Default client ID for `resource_access.<client>.roles` lookups. |
| `JWKS_CACHE_LIFESPAN` | `300` | Seconds before a normal JWKS refetch. |
| `JWKS_MIN_REFETCH_INTERVAL` | `30` | Minimum seconds between forced refetches triggered by an unknown `kid` — a DoS guard against random `kid`s forcing unlimited outbound requests. |
| `HTTP_TIMEOUT` | `5` | Seconds for the JWKS fetch. |
| `USER_CLASS` | `"django_keycloak_jwt.principal.KeycloakUser"` | Dotted path; subclass to add fields. |
| `AUTH_HEADER_REALM` | `"api"` | Used in `WWW-Authenticate: Bearer realm="..."`. |
| `USER_MODEL_ENABLED` | `False` | Opt-in: resolve/cache a real `AUTH_USER_MODEL` row instead of the claims-only `KeycloakUser`. See [Resolving a local user](#resolving-a-local-user-optional). |
| `USER_MODEL_LOOKUP_CLAIM` | `"sub"` | Claim used to find the local row. |
| `USER_MODEL_LOOKUP_FIELD` | `None` | Required if `USER_MODEL_ENABLED`. Field on `AUTH_USER_MODEL` matched against `USER_MODEL_LOOKUP_CLAIM`. Must not also appear in `USER_MODEL_FIELD_MAP` (system check error) — use a dedicated field, not `username`/`email`. |
| `USER_MODEL_FIELD_MAP` | `{"email": "email", "given_name": "first_name", "family_name": "last_name", "preferred_username": "username"}` | Claim → model field, synced on every cache-miss create/update. |
| `USER_MODEL_AUTO_CREATE` | `True` | Create the row on first sight of a claim value if `False` and nothing matches, an `AuthenticationFailed(code="user_not_provisioned")`/`401` is raised instead. |
| `USER_MODEL_CACHE_TTL` | `300` | Seconds the resolved row is cached for. |
| `USER_MODEL_ROLE_FIELD_MAP` | `{}` | Client role (on `ROLE_CLIENT`) → boolean model field, e.g. `{"admin": "is_superuser"}`. Re-evaluated and saved on every cache-miss resolve — a role revoked in Keycloak demotes the local user on next sync, not just grants additively. |

Run `python manage.py check` to catch misconfiguration: missing `ISSUER`/`AUDIENCE`,
a non-HTTPS issuer while `DEBUG=False`, symmetric or `none` algorithms, unknown keys
in the dict, and the `USER_MODEL_*` invariants above are all flagged.

Settings are loaded lazily and cached; `django.test.override_settings` correctly
invalidates the cache, so tests can freely override `KEYCLOAK_JWT`.

## Keycloak configuration checklist

- **Frontend client**: public client, PKCE (`S256`), standard flow only.
  `directAccessGrantsEnabled` (password grant) should be **off** in production — it's
  only useful for obtaining tokens without a browser in a test realm.
- **Audience mapper**: the frontend client needs a protocol mapper of type
  `oidc-audience-mapper` adding your backend's client ID (e.g. `my-backend`) to the
  **access token** audience. Without it, `AUDIENCE` will never match and every token
  is rejected.
- **Backend ("resource server") client**: represents this Django app. All flows
  disabled (no standard flow, no direct access grants, no service account) — it's
  only a role namespace, never used to obtain tokens itself.
- **Short access token lifespan**: since there is no session/revocation mechanism,
  the access token's `exp` is the only thing that ends access. Keep it short
  (minutes, not hours) at the realm or client level.
- **Client roles vs. realm roles**: assign roles to users either at the realm level
  (`realm_access.roles`, via `HasRealmRole`) or on the backend client
  (`resource_access.<client>.roles`, via `HasClientRole`).

## Usage

### Authentication

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_keycloak_jwt.drf.authentication.KeycloakJWTAuthentication",
    ],
}
```

On success, `request.user` is a `KeycloakUser` (or your `USER_CLASS` subclass) backed
by the verified claims — `.sub`, `.username`, `.email`, `.realm_roles`,
`.client_roles()`, etc. On failure: no/other-scheme header → anonymous (falls through
to other authenticators); malformed/invalid/expired token → `401`; JWKS temporarily
unreachable → `503`.

### Permissions

```python
from django_keycloak_jwt.drf.permissions import HasClientRole, HasRealmRole


class NoteListCreateView(ListCreateAPIView):
    def get_permissions(self):
        if self.request.method == "POST":
            return [HasClientRole.of("editor")()]  # ROLE_CLIENT by default
        return [IsAuthenticated()]


class StaffOnlyView(APIView):
    permission_classes = [HasRealmRole.of("staff")]
```

`HasClientRole.of("editor", client_id="some-other-client")` targets a specific client
instead of `ROLE_CLIENT`. Both accept multiple roles (`.of("a", "b")`), all required.

### The `owner_sub` pattern

There is no `auth.User` to have a `ForeignKey` to. To associate application data with
a Keycloak user, store their `sub` claim directly:

```python
class Note(models.Model):
    owner_sub = models.UUIDField(db_index=True)  # not a FK to auth.User
    text = models.TextField()


# in the view
serializer.save(owner_sub=request.user.sub)
Note.objects.filter(owner_sub=request.user.sub)
```

See `example_project/notes/` for a complete example.

### Resolving a local user (optional)

Set `USER_MODEL_ENABLED: True` to have `request.user` become a real
`AUTH_USER_MODEL` instance instead of the claims-only `KeycloakUser`, resolved from
verified claims, cached in Django's default cache, and kept fresh via
`post_save`/`post_delete` signals on `AUTH_USER_MODEL`:

```python
KEYCLOAK_JWT = {
    "ISSUER": "https://kc.example.com/realms/myrealm",
    "AUDIENCE": "my-backend",
    "USER_MODEL_ENABLED": True,
    "USER_MODEL_LOOKUP_CLAIM": "sub",
    "USER_MODEL_LOOKUP_FIELD": "keycloak_sub",  # a dedicated field on your user model
}
```

```python
class User(AbstractUser):
    keycloak_sub = models.UUIDField(unique=True, null=True, blank=True, db_index=True)
```

The resolved instance always carries a `.keycloak` attribute — a `KeycloakUser` (or
your `USER_CLASS`) wrapping the same verified claims — so role/claim helpers stay
reachable: `request.user.keycloak.sub`, `.realm_roles`, `.client_roles()`.
`HasRealmRole`/`HasClientRole` accept either shape automatically. The `owner_sub`
pattern above still applies; use `request.user.keycloak.sub`, not `request.user.sub`,
once this is on.

**This requires a process-shared cache backend** (Redis, Memcached) in any
multi-worker deployment — with the default per-process `LocMemCache`, a user edited
or deleted in one worker won't invalidate the cached copy held by another (flagged by
the `django_keycloak_jwt.W003` system check). The resource-server authentication path
otherwise makes zero DB queries per request except the first request for a given
user after cache expiry/invalidation ("fetch once, cache" — not "fetch never").

### Django admin login (optional)

Django admin is a cookie/session HTML app — a browser can't attach an
`Authorization: Bearer` header to a page load, so this is a genuinely separate
feature from the stateless API path above, shipped as its own Django app,
`django_keycloak_jwt.admin_login`, so nothing here affects a project that doesn't
install it. It drives a real Authorization Code + PKCE redirect to Keycloak from the
admin login page, then starts a normal Django session — from that point on, admin
behaves exactly as it always has (session, CSRF, `LogEntry`, everything).

It's built on the resolver above, so `USER_MODEL_ENABLED` (with a non-empty
`USER_MODEL_ROLE_FIELD_MAP`) is required.

**1. Register a second, dedicated Keycloak client** — public, PKCE (`S256`),
standard flow, *no client secret*. Even though the code exchange happens
server-side in a Django view, PKCE's `code_verifier` already proves possession of
the original request; a secret would be one more credential to manage for no
additional protection. Assign whatever client roles (on `ROLE_CLIENT`) you intend to
map to `is_staff`/`is_superuser`.

**2. Settings:**

```python
INSTALLED_APPS = [
    ...,
    "django.contrib.sessions",
    "django.contrib.admin",
    "django_keycloak_jwt.admin_login",
]

MIDDLEWARE = [
    ...,
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Self-gating (no-op for sessions without Keycloak state), safe to add globally:
    "django_keycloak_jwt.admin_login.middleware.KeycloakAdminSessionMiddleware",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_keycloak_jwt.admin_login.backends.KeycloakAdminBackend",
]

KEYCLOAK_JWT = {
    ...,
    "USER_MODEL_ENABLED": True,
    "USER_MODEL_ROLE_FIELD_MAP": {"admin-role-name": "is_superuser"},
}

KEYCLOAK_JWT_ADMIN = {
    "CLIENT_ID": "django-admin",
    "LOGOUT_END_SESSION": True,  # also redirect through Keycloak's end_session_endpoint
}
```

`AUTHORIZATION_ENDPOINT`/`TOKEN_ENDPOINT`/`END_SESSION_ENDPOINT` are resolved from
Keycloak's OIDC discovery document (`.well-known/openid-configuration`) if left
unset; set them explicitly if the internal URL Django uses to reach Keycloak differs
from the public one the browser redirects to.

**3. urls.py** — swap in the Keycloak-aware admin site (in place, so every
existing `admin.site.register(...)` call, including `django.contrib.auth`'s own
`User`/`Group` admin, keeps working unmodified) and wire up the login/callback/logout
views:

```python
from django.contrib import admin
from django.urls import include, path
from django_keycloak_jwt.admin_login.admin_site import KeycloakAdminSite

admin.site.__class__ = KeycloakAdminSite

urlpatterns = [
    ...,
    path("admin-login/", include("django_keycloak_jwt.admin_login.urls")),
    path("admin/", admin.site.urls),
]
```

**Login is gated on roles.** The callback rejects (`403`) any login where none of
`USER_MODEL_ROLE_FIELD_MAP`'s fields resolved `True` — a valid Keycloak login alone
isn't enough to reach admin. The `django_keycloak_jwt.admin_login.E004` check refuses
to start if that map is empty, since that would silently admit every Keycloak user
with no flags ever set.

**The session tracks the token, not the other way around.** On login,
`request.session` is set to expire with the access token (typically a few minutes,
per Keycloak's short-lived-token guidance); `KeycloakAdminSessionMiddleware` silently
renews it in the background using the stored `refresh_token` as long as Keycloak
keeps honoring it, and logs the session out the moment a refresh attempt fails —
there's no separate, longer-lived Django session lifetime to reason about.

## Security notes

- **Revocation only happens at `exp`.** There is no session to invalidate and no
  per-request call to Keycloak, so a compromised token remains valid until it
  expires. Keep `accessTokenLifespan` short in Keycloak.
- **JWKS refetch is rate-limited.** An unknown `kid` triggers at most one forced
  refetch per `JWKS_MIN_REFETCH_INTERVAL`; this bounds outbound requests even if
  something floods your API with tokens carrying random/garbage `kid`s.
- **JWKS outages return `503`, not `401`.** A network/parse failure fetching the
  JWKS is a distinct failure mode from an invalid token — it's surfaced as
  `auth_unavailable` so callers (and monitoring) can tell "Keycloak is down" apart
  from "this token is bad". If a previously-fetched key for the requested `kid` is
  still cached, it's used instead (with a warning logged), so a brief Keycloak
  outage doesn't necessarily interrupt already-known clients.
- **No secrets or raw tokens are ever logged.** Only `kid`, `iss`, and error class
  names appear in log output.
- **The authentication path makes zero database queries by default**, and in
  steady-state even with `USER_MODEL_ENABLED` on (see above). Enforced by a unit test
  (`django_assert_num_queries(0)`) and an e2e test against a real Postgres +
  Keycloak.

## Running tests locally

```bash
uv sync --group dev

make lint        # ruff check + ruff format --check
make typecheck    # mypy --strict on src/django_keycloak_jwt
make test         # unit tests, coverage gate at 90%

# End-to-end (needs Docker):
make e2e-up        # starts Postgres + Keycloak via docker-compose, waits for health
make e2e           # migrates example_project, runs pytest -m e2e
make e2e-down       # tears the stack down
```

Unit tests need no network access beyond a local fixture HTTP server; e2e tests need
Docker (Postgres 17 + Keycloak, per `docker-compose.yml`) and talk to a real Keycloak
realm imported from `e2e/keycloak/realm-test.json`.
