# Task: `keycloak_jwt` — stateless Keycloak JWT authentication for Django REST Framework

You are implementing a reusable Django app (pip-installable package) that authenticates DRF requests
using Keycloak-issued access tokens (JWT, RS256) sent as `Authorization: Bearer <token>`.
Django acts purely as an **OAuth2 resource server**: it never creates sessions, never stores users,
never calls Keycloak per request. Only DRF support in this phase. Django Channels support comes
later, so keep the validation core framework-agnostic.

Work in the phases at the end of this document. After each phase, run the full test suite and lint,
then stop and summarize what was done before starting the next phase.

---

## 0. Ground rules

- **Verify APIs against the installed versions** (PyJWT, DRF, Django, pytest-django, Keycloak admin
  REST API). Do not rely on memory for signatures or config keys; read the installed source or docs.
- Pin exact current stable versions when you add them; check what is current first.
- Never log tokens, token fragments, or secrets. Log `kid`, `iss`, error class only.
- No Django sessions, no `auth.User` lookups, no DB queries in the auth path. A test must enforce this.
- Fail closed: any validation doubt → reject.
- Type hints everywhere; `ruff` (lint + format) clean; `mypy --strict` on the package (not tests).
- Keep the package small and dependency-light: runtime deps are `Django`, `djangorestframework`,
  `PyJWT[crypto]` only.

## 1. Tooling & repo layout

- Python ≥ 3.13 (`requires-python = ">=3.13"`), Django ≥ 6.0,<7 (`Django>=6.0,<7`).
- DRF: the newest release; before pinning, verify it declares/tests Django 6.0 support. If it
  does not officially yet, note that in the README and CI, and do not work around it silently.
- Stubs (`django-stubs`, `djangorestframework-stubs`): pick versions compatible with Django 6.0;
  if none exist yet, run mypy with the closest release and document it.
- Use modern syntax freely (PEP 695 generics, `type` aliases, `typing.override`); no
  compatibility shims for older Pythons or Djangos.
- Use `uv` for env/deps, `hatchling` build backend, `pyproject.toml` only (no setup.py).
- `pytest`, `pytest-django`, `pytest-cov`, `requests` (e2e only), `ruff`, `mypy`, `django-stubs`,
  `djangorestframework-stubs`.
- Coverage gate: ≥ 90 % on `src/keycloak_jwt` from unit tests alone.

```
.
├── pyproject.toml
├── README.md                  # install, settings reference, Keycloak client setup, security notes
├── CHANGELOG.md
├── docker-compose.yml         # local e2e env: keycloak + postgres (mirrors CI)
├── Makefile                   # lint, typecheck, test, e2e-up, e2e, e2e-down
├── src/keycloak_jwt/
│   ├── __init__.py
│   ├── apps.py                # AppConfig; registers system checks
│   ├── conf.py                # settings loading, defaults, validation
│   ├── checks.py              # Django system checks for misconfiguration
│   ├── exceptions.py          # TokenInvalid, TokenExpired, KeysUnavailable (framework-agnostic)
│   ├── jwks.py                # thread-safe JWKS cache with rotation handling
│   ├── validation.py          # validate_token(raw: str) -> Claims  (framework-agnostic core)
│   ├── principal.py           # KeycloakUser (claims-backed, not a model)
│   └── drf/
│       ├── __init__.py
│       ├── authentication.py  # KeycloakJWTAuthentication
│       ├── permissions.py     # HasRealmRole, HasClientRole
│       └── schema.py          # optional drf-spectacular OpenApiAuthenticationExtension
├── tests/                     # unit tests (no network, no Keycloak)
│   ├── conftest.py
│   ├── settings.py
│   └── ...
├── example_project/           # minimal Django project used by e2e tests
│   ├── manage.py
│   ├── example_project/settings.py
│   └── notes/                 # tiny app with a Note model (Postgres)
├── e2e/
│   ├── keycloak/realm-test.json
│   ├── conftest.py
│   └── test_*.py
└── .github/workflows/ci.yml
```

## 2. Settings (`conf.py`)

Single dict `KEYCLOAK_JWT` in Django settings. Load lazily, cache, and reset on Django's
`setting_changed` signal (so `override_settings` works in tests).

| Key | Default | Notes |
|---|---|---|
| `ISSUER` | required | e.g. `https://kc.example.com/realms/myrealm`. Exact match against `iss`. |
| `AUDIENCE` | required | str or list. Token `aud` (str or list) must contain at least one. |
| `JWKS_URL` | `None` | If `None`, derive `f"{ISSUER}/protocol/openid-connect/certs"`. Separate key so an internal URL can differ from the public issuer. |
| `ALGORITHMS` | `["RS256"]` | Allowlist. Reject `none` and any `HS*` even if configured (system check error). |
| `LEEWAY` | `10` | Seconds, for `exp`/`nbf`/`iat`. |
| `ALLOWED_AZP` | `None` | Optional list of client IDs allowed as `azp`. |
| `REQUIRED_TYP` | `"Bearer"` | Keycloak sets `typ`: `Bearer` for access, `ID` for id tokens, `Refresh` for refresh tokens. |
| `ROLE_CLIENT` | `None` | Default client ID for `resource_access.<client>.roles` lookups. |
| `JWKS_CACHE_LIFESPAN` | `300` | Seconds before a normal refetch. |
| `JWKS_MIN_REFETCH_INTERVAL` | `30` | Minimum seconds between forced refetches on unknown `kid` (DoS guard). |
| `HTTP_TIMEOUT` | `5` | Seconds for JWKS fetch. |
| `USER_CLASS` | `"keycloak_jwt.principal.KeycloakUser"` | Dotted path; allows subclassing. |
| `AUTH_HEADER_REALM` | `"api"` | Used in `WWW-Authenticate: Bearer realm="..."`. |

System checks (`checks.py`): missing `ISSUER`/`AUDIENCE`, non-HTTPS issuer when `DEBUG=False`
(warning), symmetric or `none` algorithms (error), unknown keys in the dict (warning).

## 3. JWKS handling (`jwks.py`)

- Wrap `jwt.PyJWKClient` (or implement a thin fetcher if PyJWKClient cannot meet the requirements
  below — check its current constructor: headers, timeout, caching options).
- **Always send a `User-Agent` header** (Keycloak may reject requests without one).
- Module-level singleton keyed by JWKS URL, guarded by a `threading.Lock`.
- Lookup flow for a token's `kid`:
  1. Key in cache and cache fresh → use it.
  2. Unknown `kid` → forced refetch **only if** `JWKS_MIN_REFETCH_INTERVAL` has elapsed since the last
     forced refetch; otherwise reject as invalid. This handles key rotation without letting random
     `kid`s trigger unlimited outbound requests.
  3. Only consider keys with `use == "sig"` (or no `use`) and whose `alg` matches the token's `alg`.
     Keycloak's JWKS also contains `enc` keys — ignore them.
- Network/HTTP/parse failure → raise `KeysUnavailable` (maps to 503, not 401). If a stale cached key
  for the requested `kid` exists, it may be used (stale-while-error), log a warning.
- Provide `reset_jwks_cache()` for tests.

## 4. Validation core (`validation.py`)

`validate_token(raw: str) -> dict[str, Any]` — no Django request objects, no DRF imports.

Order matters:
1. Parse the unverified header. Reject if malformed, if `alg` not in `ALGORITHMS`, or if `kid` missing.
   The algorithm check happens **before** any key lookup.
2. Resolve signing key via `jwks.py`.
3. `jwt.decode(...)` with `algorithms=ALGORITHMS` (never the token's own header value alone),
   `audience`, `issuer`, `leeway`, and `options={"require": ["exp", "iat", "iss", "sub", "aud"]}`.
4. Check `typ == REQUIRED_TYP` (case-sensitive).
5. If `ALLOWED_AZP` set, check `azp` is in it.
6. Map PyJWT exceptions: `ExpiredSignatureError` → `TokenExpired`; everything else → `TokenInvalid`
   with a short, non-sensitive reason string.

## 5. Principal (`principal.py`)

`KeycloakUser` — a plain class, **not** a Django model and not an `AbstractBaseUser`.

- `claims` (read-only mapping), `sub`, `pk`/`id` (= `sub`), `username` (= `preferred_username` or `sub`),
  `email`, `given_name`, `family_name`, `azp`.
- `is_authenticated = True`, `is_anonymous = False`, `is_active = True`, `is_staff = False`,
  `is_superuser = False`.
- `realm_roles: frozenset[str]` from `realm_access.roles`.
- `client_roles(client_id: str | None = None) -> frozenset[str]` from `resource_access.<client>.roles`,
  defaulting to `ROLE_CLIENT`.
- `has_realm_role(role)`, `has_client_role(role, client_id=None)`.
- `get_username()`, `__str__`, `__eq__`/`__hash__` by `sub`.
- `has_perm`/`has_perms`/`has_module_perms` return `False` (Django permission system is not used).
- Must survive missing optional claims gracefully.

Document in README: to own data, store `sub` in a `UUIDField`/`CharField` (`owner_sub`), not a FK to
`auth.User`.

## 6. DRF integration

### `KeycloakJWTAuthentication(BaseAuthentication)`
- No `Authorization` header, or a scheme other than `Bearer` (case-insensitive) → return `None`
  (lets other authenticators run; request stays anonymous).
- `Bearer` with missing token, or extra parts → `AuthenticationFailed` (401).
- `TokenExpired` → 401, `code="token_expired"`.
- `TokenInvalid` → 401, `code="token_not_valid"`.
- `KeysUnavailable` → a custom `APIException` subclass, status 503, `code="auth_unavailable"`.
- Success → `(USER_CLASS(claims), raw_token)`.
- `authenticate_header()` → `Bearer realm="<AUTH_HEADER_REALM>"` so DRF returns 401 instead of 403.

### Permissions
- `HasRealmRole` and `HasClientRole` base classes with a `required_roles` attribute
  (all required) plus a convenience factory, e.g. `HasRealmRole.of("staff")` returning a subclass.
- `HasClientRole` optionally takes a `client_id`; defaults to `ROLE_CLIENT`.
- Return `False` for anonymous users or non-`KeycloakUser` principals.

### drf-spectacular (optional import)
If `drf_spectacular` is importable, provide an `OpenApiAuthenticationExtension` declaring
HTTP bearer / JWT. Must not break when drf-spectacular is not installed.

## 7. Unit tests (`tests/`)

No network access to anything but a local fixture server. Use `cryptography` to generate RSA keys
per session, and a **real local HTTP server fixture** (threaded `http.server` on a random port)
that serves a mutable JWKS document and can be told to return 500 / hang / count requests.
A token factory fixture builds tokens with overridable claims/headers.

Must cover at minimum:
- valid token → 200, `request.user` is `KeycloakUser` with correct fields and roles
- **zero DB queries** during authentication (`django_assert_num_queries(0)`)
- no header → anonymous; `Token abc` / `Basic ...` → ignored (other schemes)
- `Bearer` without token, `Bearer a b` → 401
- expired → 401 `token_expired`; `nbf` in future → 401; within `LEEWAY` → accepted
- wrong `iss`, wrong `aud`, missing `aud`, `aud` as list containing ours → accepted
- `typ` = `ID` and `Refresh` → 401
- `azp` not in `ALLOWED_AZP` → 401
- `alg: none` → 401; **algorithm confusion**: HS256 token signed with the RSA public key as secret → 401
- tampered payload / signature → 401
- unknown `kid` → one refetch → success after rotation (server now serves new key)
- unknown `kid` spam → at most one refetch per `JWKS_MIN_REFETCH_INTERVAL` (assert request count)
- JWKS server 500 / timeout with empty cache → 503 `auth_unavailable`
- JWKS server down but stale key cached → accepted, warning logged
- JWKS request carries a `User-Agent` header
- `enc` keys in JWKS are ignored
- `WWW-Authenticate` header present on 401
- permission classes: realm role, client role (default and explicit client), anonymous denied
- system checks fire for each misconfiguration listed in §2
- `override_settings` changes take effect (settings cache reset)
- caplog assertion: no raw token string ever appears in logs

## 8. Example project (for e2e)

`example_project/` — minimal Django project, Postgres via `DATABASE_URL`-style env vars
(`POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`).
No `django.contrib.sessions`, no session middleware. `KEYCLOAK_JWT` configured from env
(`KC_ISSUER`, `KC_AUDIENCE`, `KC_ROLE_CLIENT`), `LEEWAY` 0 for e2e.

App `notes`: model `Note(id, owner_sub: UUIDField(db_index), text, created_at)`.

Endpoints:
- `GET /api/public/` — AllowAny
- `GET /api/me/` — IsAuthenticated; returns `sub`, `username`, `email`, `realm_roles`, `client_roles`
- `GET /api/notes/` — IsAuthenticated; lists only the caller's notes
- `POST /api/notes/` — requires client role `editor` on client `api`; stores `owner_sub = request.user.sub`
- `GET /api/staff/` — requires realm role `staff`

## 9. Keycloak test realm (`e2e/keycloak/realm-test.json`)

Imported at container start. Realm `test`, `accessTokenLifespan` 300.

Clients:
- `api` — represents this backend. All flows disabled (no standard flow, no direct access grants,
  no service account). Client roles: `reader`, `editor`.
- `frontend` — public client, PKCE S256, redirect URI `http://localhost:5173/*`.
  **Test realm only:** `directAccessGrantsEnabled: true` so e2e tests can obtain tokens via the
  password grant without a browser. README must state this is never enabled in production.
  Protocol mapper `oidc-audience-mapper` adding audience `api` to the **access token**.
- `frontend-short` — same as `frontend` but client attribute `access.token.lifespan: "5"`
  (for the expiry e2e test).
- `other-client` — public, direct access grants on, **no** audience mapper (tokens must be rejected).

Realm role `staff`. Users (with `emailVerified: true`, `firstName`, `lastName`, `email` set and
`requiredActions: []` — otherwise the password grant fails with "Account is not fully set up"):
- `alice` / `alice-pass` — realm role `staff`, client roles `api: editor, reader`
- `bob` / `bob-pass` — no roles

Verify the import works by starting Keycloak locally and requesting a token for each client
before writing tests against it.

## 10. E2E tests (`e2e/`)

Marked `@pytest.mark.e2e`, excluded from the default run (`-m "not e2e"` in pytest config).
Use pytest-django's `live_server` against the real Postgres and real HTTP via `requests`.
A session fixture waits for Keycloak readiness and fetches tokens from
`{KC_URL}/realms/test/protocol/openid-connect/token` (password grant).

Scenarios:
- alice `GET /api/me/` → 200, `sub` matches token, roles correct
- alice `POST /api/notes/` → 201; row exists in Postgres with alice's `sub`; alice `GET` sees it;
  bob `GET` does not
- bob `POST /api/notes/` → 403; bob `GET /api/staff/` → 403; alice `GET /api/staff/` → 200
- no token → 401 with `WWW-Authenticate`; `/api/public/` → 200 without token
- token from `other-client` → 401 (audience)
- refresh token as bearer → 401; id token (request `scope=openid`) as bearer → 401
- tampered token (flip a payload char) → 401
- `frontend-short` token: works immediately, after ~7 s → 401 `token_expired`
- **key rotation**: via Keycloak admin REST API (admin-cli, master realm), add a new `rsa-generated`
  key provider with higher priority to realm `test`; fetch a new token; assert its `kid` differs
  and the API accepts it (proves forced refetch). Old token still accepted while old key is
  still published. Clean up the provider afterwards.
- authentication path makes no DB queries: assert via a request to `/api/me/` wrapped in
  `CaptureQueriesContext` in a non-live test using a real Keycloak token.

## 11. Local environment (`docker-compose.yml`, `Makefile`)

Mirror CI exactly: Postgres 17 on 5432, Keycloak (pin latest 26.x tag) on 8080 with management
port 9000, `start-dev --import-realm`, realm JSON mounted to `/opt/keycloak/data/import`,
`KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD`, `KC_HEALTH_ENABLED=true`.
Django runs on the host (so the issuer is `http://localhost:8080/realms/test` for both token
requests and validation). `make e2e` waits for `http://localhost:9000/health/ready`.

## 12. GitHub Actions (`.github/workflows/ci.yml`)

Triggers: push to `main`, pull requests. Use `astral-sh/setup-uv`, cache deps.

Jobs:
1. **lint** — `ruff check`, `ruff format --check`, `mypy`.
2. **unit** — matrix: Python 3.13/3.14 × Django 6.0 (add newer 6.x releases as they appear). `pytest -m "not e2e" --cov --cov-fail-under=90`.
3. **build** — `uv build`, check the wheel installs into a clean venv and `import keycloak_jwt` works;
   upload `dist/` as artifact.
4. **e2e** — `needs: [unit]`, single Python/Django combo.

**Important constraint for e2e:** GitHub Actions `services:` containers cannot take a command
(`start-dev`) and are created **before** `actions/checkout`, so they cannot mount the realm JSON
from the repo. Therefore:
- Run **Postgres as a `services:` container** (with `--health-cmd pg_isready` options).
- Start **Keycloak in a step after checkout** with `docker run -d` (same image tag, env, volume
  mount of `e2e/keycloak`, `start-dev --import-realm`, ports 8080 and 9000), then poll
  `/health/ready` with a timeout (~120 s) and fail clearly if it never becomes ready.
- Run migrations for `example_project`, then `pytest -m e2e`.
- On failure: `docker logs keycloak` step with `if: failure()`.

Keep the Keycloak image tag and realm path in one place (workflow `env:`), and the same values in
`docker-compose.yml`.

## 13. README

Sections: what it is / is not (resource server only, no login flow, no user sync), install,
settings reference (§2 table), Keycloak configuration checklist (public client + PKCE, audience
mapper, short access token lifespan, direct access grants off in prod), usage (auth class,
permissions, `owner_sub` pattern), security notes (revocation happens only at `exp` → keep tokens
short; JWKS refetch rate limit; 503 on key outage), running tests locally.

---

## Phases & acceptance criteria

1. **Scaffold** — layout, pyproject, tooling, empty package importable, CI lint + unit jobs green
   with a placeholder test.
2. **Core** — `conf`, `checks`, `exceptions`, `jwks`, `validation`, `principal` + their unit tests.
   Coverage ≥ 90 % on these modules.
3. **DRF** — authentication, permissions, optional schema extension + unit tests (§7 complete).
4. **Example project + Keycloak realm** — `docker-compose up` works locally; manual token fetch
   for all four clients succeeds; `example_project` migrates on Postgres.
5. **E2E** — all §10 scenarios pass locally via `make e2e`.
6. **CI e2e + build** — full workflow green on a PR.
7. **Docs** — README and CHANGELOG complete.

Out of scope for now: Django Channels middleware, token introspection, user/group sync,
login/logout views. Keep `validation.py` free of DRF imports so Channels support can reuse it.
