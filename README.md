# django-keycloak-jwt

Stateless Keycloak JWT authentication for Django REST Framework.

Django acts purely as an **OAuth2 resource server**: it validates Keycloak-issued
`RS256` access tokens on every request against Keycloak's published JWKS. It never
creates sessions, never stores users, and never calls Keycloak per request beyond
periodic JWKS refresh.

## What this is

- A DRF `BaseAuthentication` class that validates `Authorization: Bearer <token>`
  against a Keycloak realm's public keys.
- A claims-backed request principal (`request.user`) with realm/client role helpers.
- Permission classes for realm and client roles.
- A framework-agnostic validation core (`django_keycloak_jwt.validation`) with no Django or
  DRF imports, so it can be reused outside DRF (e.g. a future Django Channels
  middleware).

## What this is not

- **Not a login flow.** There are no views for redirecting to Keycloak, handling the
  authorization code exchange, or logging users out. Token acquisition is entirely
  the frontend's job (Authorization Code + PKCE against Keycloak directly).
- **Not a user store.** There is no `auth.User` row per Keycloak user, no signal that
  creates one on first login, no local profile table. The verified JWT claims *are*
  the user.
- **Not a session system.** No `django.contrib.sessions`, no CSRF cookie, no server-side
  logout. Revoking access means letting the (short-lived) token expire — see
  [Security notes](#security-notes).
- **Not token introspection.** Tokens are verified locally via signature + claims;
  Keycloak is only contacted to fetch its public keys (JWKS), not per request.

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

Run `python manage.py check` to catch misconfiguration: missing `ISSUER`/`AUDIENCE`,
a non-HTTPS issuer while `DEBUG=False`, symmetric or `none` algorithms, and unknown
keys in the dict are all flagged.

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
- **The authentication path makes zero database queries.** Enforced by a unit test
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
