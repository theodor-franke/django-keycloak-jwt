# Task: `admin_login` cookie mode — stateless Keycloak JWT auth for Django admin

## 0. Context

`admin_login` (added after the original `KEYCLOAK_JWT_SPEC.md`) currently has exactly one
strategy: redirect to a **dedicated** Keycloak client via Authorization Code + PKCE, then
`django_login()` a real Django session. The README is explicit about why: *"Django admin is a
cookie/session HTML app... necessarily does use sessions."* That's still true in the sense that
admin needs *some* cookie — but it doesn't have to be a Django session cookie carrying a
server-side-stored identity. It can instead be the verified JWT itself, re-validated on every
request exactly the way the DRF path already does it. That's the one place left in this library
that isn't stateless, and this task closes that gap as an **additional, opt-in mode** —
`COOKIE_MODE` — not a replacement. The existing session mode must keep working, unmodified, for
anyone not opting in.

Concretely, requested behavior: the admin login redirect uses the **same OIDC client the SPA
frontend already uses** (not a second dedicated `django-admin`-style client), the resulting
**access token is stored in a cookie** (not a session), that cookie is sent on every subsequent
request, and each request **re-validates it from scratch** via the existing stateless core
(`validation.validate_token` + `user_resolution.resolve_user`) — no server-side identity storage
at all.

Read `README.md`'s "Django admin login" section and `src/django_keycloak_jwt/admin_login/*`
(`conf.py`, `views.py`, `oidc.py`, `middleware.py`, `backends.py`, `admin_site.py`, `checks.py`,
`urls.py`) in full before starting. Everything below assumes you've read them.

## 1. Feasibility assessment — read this before writing any code

This was checked against the actual installed package (not assumed from memory). Conclusion:
**feasible**, with the constraints below. If any of the "must verify" items turns out false,
stop and report back rather than working around it silently.

- **Reusable as-is:** `validation.validate_token()` and `user_resolution.resolve_user()` are
  exactly what's needed and need zero changes — they're already framework-agnostic / claims-in,
  user-out. `admin_login.oidc`'s PKCE/state generation, `resolve_endpoints`, `build_authorization_url`,
  and `exchange_code` are also reusable unchanged — they don't know or care what happens to the
  tokens afterward.
- **"Same FE client" is a config value, not a code change.** `KEYCLOAK_JWT_ADMIN['CLIENT_ID']` is
  already just a string; pointing it at the frontend's client ID works today. What changes is the
  checklist: instead of *"register a second, dedicated client,"* the Keycloak-side step becomes
  *"add the admin callback URL to the frontend client's existing Valid Redirect URIs."* Since the
  frontend is almost certainly a public client with PKCE already (required for a browser SPA),
  no client-type change is needed either. Document this, don't code it.
- **Which token goes in the cookie:** the **access token**, not the ID token. `validate_token()`
  checks `aud == KEYCLOAK_JWT['AUDIENCE']` (the backend resource server) and `typ == 'Bearer'` —
  that's the access token's shape, the exact one the SPA already sends as
  `Authorization: Bearer <access_token>` for API calls. The ID token (`aud` = client ID, `typ` =
  `'ID'`) is what the *current* session mode validates via `oidc.validate_id_token` — don't reuse
  that function here, it checks the wrong audience/typ for this purpose.
- **Cookie size is the real risk — must verify empirically.** RS256 access tokens with realm +
  client roles embedded commonly run 1–3 KB; browsers cap individual cookies around 4 KB, and
  combined request header size (all cookies + other headers) is commonly capped around 8 KB by
  reverse proxies (nginx `large_client_header_buffers` et al.) — tighter configs exist. **Before
  building anything else**, obtain a real access token from the e2e realm's `frontend` client
  (which already has roles/mappers configured) and measure its encoded length. If it doesn't
  comfortably fit (say, under ~3 KB to leave headroom for other cookies on the same requests —
  CSRF cookie, Django session cookie if one happens to exist, language cookie, etc.), **stop and
  report back** — don't build cookie-chunking to route around it; that's a scope decision for a
  human, not something to improvise.

  A rough sanity check (RS256, realistic claim set: a handful of realm roles, two clients' worth of
  resource_access roles, standard profile claims — not pulled from a real server, but shaped like
  one) came out to **~1.5 KB** for the encoded token, ~1.56 KB as a full `Set-Cookie` line. That's
  comfortably inside budget for a realm with a modest number of roles. This is a *plausibility*
  check, not the real measurement Phase 1 requires — a realm with many fine-grained client roles
  could be meaningfully larger, so still measure against the actual target realm before building
  anything further.
- **CSRF is unaffected.** Django's CSRF protection is cookie-based by default
  (`CSRF_USE_SESSIONS=False` is Django's own default) — it doesn't depend on
  `django.contrib.sessions` or on how `request.user` got populated. No special handling needed.
- **`django.contrib.sessions` does not need to be removed.** Django admin's message framework
  (`django.contrib.messages`) defaults to session-backed storage, and removing
  `django.contrib.sessions` project-wide to go "fully sessionless" is **out of scope** — that's a
  much bigger decision for the consuming project, not this library. `COOKIE_MODE` only needs to
  guarantee that **authentication** (how `request.user` gets set) never depends on a session. A
  project can keep `django.contrib.sessions` installed for admin's other conveniences and still be
  in `COOKIE_MODE` for auth. Don't add any check that forces sessions off.
- **No background refresh in v1.** The current session mode keeps a `refresh_token` in the
  session and silently renews near expiry (`KeycloakAdminSessionMiddleware`). Cookie mode does
  **not** do this — ship it without a refresh-token cookie. On access-token expiry, the new
  per-request middleware simply fails validation and leaves the request anonymous; Django admin's
  own `has_permission` check then redirects back into the login view exactly like a first-time
  visit, which re-runs the Authorization Code redirect against Keycloak. Because the browser still
  holds Keycloak's own SSO session cookie, this round-trip is expected to be invisible (no login
  form shown) as long as that SSO session is alive — this matches what was asked for ("redirects
  to the IDP again, gets a new token") and keeps the feature simple. Document this explicitly as
  the current tradeoff; a refresh-cookie mode can be a later addition if it proves too disruptive
  in practice, but don't build it now.
- **Blast radius of the cookie:** if sent on every same-origin request (as requested), it's also
  attached to calls under e.g. `/api/...`. This is harmless — `KeycloakJWTAuthentication` only
  reads the `Authorization` header, never cookies, so an incidental admin cookie on an API request
  changes nothing. Still, default the cookie's `Path` to the admin mount point rather than `/`, to
  shrink exposure for no cost (see settings below).
- **Logout coupling:** since login now goes through the *same* Keycloak client as the SPA, ending
  the SPA's Keycloak SSO session (e.g. the frontend's own logout) will also prevent a silent
  re-auth redirect for admin next time its cookie expires — that's correct/expected (one login,
  shared), not a bug. Mention it in the README, don't try to decouple it.

## 2. Ground rules

- Don't duplicate validation logic. Every claims-checking step must go through the existing
  `validation.validate_token` / `user_resolution.resolve_user`, same as the DRF path.
- No new runtime dependencies. `django.core.signing` (stdlib-adjacent, already a Django import
  elsewhere in this codebase's style) is sufficient for the short-lived state/PKCE-verifier
  handshake cookie — don't reach for a new session/cache backend.
- Fully backward compatible: `COOKIE_MODE` defaults to `False`; every existing test, setting, and
  documented behavior for session mode must keep passing and working unmodified. Do not change the
  default behavior of anyone currently using `admin_login` without `COOKIE_MODE=True`.
- Never log tokens or cookie values, same as the rest of the package.
- Fail closed: any validation doubt on the cookie's token → treat as anonymous, not as a crash.
- Type hints everywhere; `ruff` + `mypy --strict` on `src/django_keycloak_jwt` clean. Match the
  existing code's docstring style (explain *why*, not *what*; see e.g. `oidc.py`'s module
  docstring on why PKCE needs no client secret).
- Coverage ≥ 90% on the new code, consistent with the project-wide gate.

## 3. Settings additions (`admin_login/conf.py`)

Extend `DEFAULTS`, `KNOWN_KEYS`, and `KeycloakJWTAdminSettings` with:

| Key | Default | Notes |
|---|---|---|
| `COOKIE_MODE` | `False` | Opt-in switch. When `True`, `login`/`callback`/`logout` take the cookie-based branch described below instead of the session-based one. |
| `ACCESS_COOKIE_NAME` | `"kc_admin_access_token"` | Holds the raw access token. `HttpOnly`, see security notes. |
| `ACCESS_COOKIE_PATH` | `"/"` | Deliberately simple default; README should recommend scoping it to the admin mount point (e.g. `/admin`) to shrink blast radius, since the exact mount point is a project-level choice this library can't infer reliably. |
| `ACCESS_COOKIE_SECURE` | `True` | Mirror the existing pattern of making this env-overridable at the project level (same spirit as `SESSION_COOKIE_SECURE` in Django itself) — just read it as a plain setting here; don't invent env-var parsing in this library. |
| `ACCESS_COOKIE_SAMESITE` | `"Lax"` | `Strict` would break the redirect-back-from-Keycloak step (that hop is a cross-site navigation even though it's this same app redirecting out and back). |
| `STATE_COOKIE_NAME` | `"kc_admin_login_state"` | Short-lived, signed, carries the login handshake (state + PKCE verifier + post-login `next`) in `COOKIE_MODE`, replacing the three `request.session[...]` keys used in session mode. One cookie, not three — see §4.1. |
| `STATE_COOKIE_MAX_AGE` | `300` | Seconds. Generous enough for a slow IdP redirect, short enough that a stale one is useless. |

Validation (`checks.py`, new codes continuing the existing `django_keycloak_jwt.admin_login.E0xx`/
`W0xx` numbering):

- `COOKIE_MODE=True` with `ACCESS_COOKIE_SECURE=False` while `DEBUG=False` → **Warning**, same
  spirit as the existing `ISSUER` non-HTTPS check.
- `COOKIE_MODE=True` and `AUTHENTICATION_BACKENDS` still lists `KeycloakAdminBackend` → no error,
  it's just unused in this mode (no `django_login()` call happens) — don't warn, that's needless
  noise for a project that keeps both modes configured for a transition period.
- Unknown-key and role-map-empty checks (`E003`/`E004`/`W001`) already exist and apply unchanged
  to both modes — don't duplicate them for `COOKIE_MODE`.

## 4. Behavioral spec

### 4.1 `views.login` — cookie-mode branch

Same PKCE/state generation as today (`oidc.generate_pkce_pair`, `oidc.generate_state`). Instead of
three `request.session[...] = ...` writes, build one dict `{"state": ..., "verifier": ...,
"next": ...}`, sign it with `django.core.signing.dumps(..., salt="django_keycloak_jwt.admin_login.state")`,
and set it as `STATE_COOKIE_NAME` on the redirect response (`HttpOnly`, `max_age=STATE_COOKIE_MAX_AGE`,
`secure=ACCESS_COOKIE_SECURE`, `samesite=ACCESS_COOKIE_SAMESITE`). Build the authorization URL and
redirect exactly as today — `oidc.build_authorization_url` doesn't change.

### 4.2 `views.callback` — cookie-mode branch

Read and verify the state cookie instead of popping session keys:
`signing.loads(request.COOKIES.get(STATE_COOKIE_NAME), salt=..., max_age=STATE_COOKIE_MAX_AGE)`,
catching `signing.BadSignature`/`SignatureExpired` the same way `mock_auth`-style consumers would
(see `TokenInvalid`-style handling already used elsewhere in this view) and returning the same
`HttpResponseBadRequest("Invalid or expired login attempt. Please try again.")` on failure.
Compare `state` from the query string against the cookie's `state` exactly as today.

On success, call `oidc.exchange_code` exactly as today (same function, same args). Then, instead
of `oidc.validate_id_token` + `django_login`:

1. Validate the returned **access token** via `django_keycloak_jwt.validation.validate_token`
   (the core function, not `oidc.validate_id_token`).
2. Resolve the user via `user_resolution.resolve_user(claims)` — same role-sync, same cache, same
   `UserNotFound`/`TokenInvalid` handling as today's callback.
3. Apply the exact same role gate as today: reject (403, same message) if none of
   `KEYCLOAK_JWT['USER_MODEL_ROLE_FIELD_MAP']`'s fields resolved `True`.
4. On success: redirect to `next_url` (from the verified state cookie), and on that response:
   - Delete the state cookie.
   - Set `ACCESS_COOKIE_NAME` to the raw access token, with `max_age` computed from the token's own
     `exp` claim minus "now" (so the cookie never outlives the token — no separate, longer cookie
     lifetime to reason about, mirroring the existing session-mode design note: *"the session
     tracks the token, not the other way around"*). `HttpOnly`, `secure=ACCESS_COOKIE_SECURE`,
     `samesite=ACCESS_COOKIE_SAMESITE`, `path=ACCESS_COOKIE_PATH`.
   - Do **not** call `django_login()` — no session is created for identity purposes.

### 4.3 New middleware: `KeycloakAdminCookieMiddleware`

New file, `admin_login/cookie_middleware.py`. Self-gating like `KeycloakAdminSessionMiddleware`
(safe to add to `MIDDLEWARE` globally): a no-op whenever `COOKIE_MODE` is `False`, or the request
carries no `ACCESS_COOKIE_NAME` cookie.

Placed **after** `django.contrib.auth.middleware.AuthenticationMiddleware` in `MIDDLEWARE` (so it
runs after `request.user` has already been lazily set up, and can override it). Logic:

```
token = request.COOKIES.get(ACCESS_COOKIE_NAME)
if not token:
    return  # leave request.user as AuthenticationMiddleware left it (Anonymous, absent a session)
try:
    claims = validate_token(token)
    user = resolve_user(claims)
except (TokenInvalid, TokenExpired, UserNotFound):
    return  # fail closed: leave request.user untouched, do not raise, do not clear the cookie here
request.user = user
```

Note what this deliberately does *not* do: it does not consult `AUTHENTICATION_BACKENDS`, does not
call `django.contrib.auth.login`, does not write anything to `request.session`. Every request
re-derives identity from scratch from the cookie, which is the entire point.

Only overwrite `request.user` on success — on failure, leave whatever `AuthenticationMiddleware`
already produced (normally `AnonymousUser`), so Django admin's own unauthenticated-visitor flow
(`has_permission` → redirect to `admin:login` → `KeycloakAdminSite.login`, unchanged) handles the
"expired/missing cookie" case for free, exactly the same code path as a first-time visitor.

### 4.4 `views.logout` — cookie-mode branch

Delete `ACCESS_COOKIE_NAME` (`delete_cookie`, matching `path`). Skip `django_logout()` — there's no
session-based identity to tear down (calling it anyway would be harmless but misleading; don't).
`LOGOUT_END_SESSION` behavior (redirect through Keycloak's `end_session_endpoint`) is unchanged and
mode-independent — reuse as-is. Note in the README (§8 below) that since this shares the frontend's
Keycloak client/SSO session, this logout also ends the frontend's SSO session — intentional.

### 4.5 `admin_site.py`

No changes. `KeycloakAdminSite.login` already just redirects into `reverse("keycloak_admin_login:login")`
regardless of mode — the mode branch lives inside that view, not in the admin site class.

### 4.6 `backends.py` / `AUTHENTICATION_BACKENDS`

No changes required to `KeycloakAdminBackend`. It's simply unused when `COOKIE_MODE=True` (no
`django_login()` call happens, so nothing ever needs a backend path to stamp into a session).
Leave it as-is for session-mode users; don't make it mode-aware.

## 5. New / modified files

| File | Change |
|---|---|
| `admin_login/conf.py` | Add the 6 new settings (§3) to `DEFAULTS`, `KNOWN_KEYS`, `KeycloakJWTAdminSettings`. |
| `admin_login/checks.py` | Add the one new warning from §3. |
| `admin_login/views.py` | Branch `login`/`callback`/`logout` on `COOKIE_MODE` per §4.1/4.2/4.4. Keep the session-mode code path byte-for-byte as it is today inside the `else` branch — this is a refactor-free addition, not a rewrite. |
| `admin_login/cookie_middleware.py` | **New.** `KeycloakAdminCookieMiddleware`, §4.3. |
| `README.md` | New subsection under "Django admin login" — see §8. |
| `CHANGELOG.md` | New `[Unreleased]` entry. |

No changes to: `admin_login/oidc.py`, `admin_login/backends.py`, `admin_login/admin_site.py`,
`admin_login/middleware.py` (the existing session-refresh one — untouched, only relevant to session
mode), `admin_login/urls.py` (same three routes, same names, serve both modes), `validation.py`,
`user_resolution.py`, anything under `drf/`.

## 6. Unit tests (new file `tests/test_admin_login_cookie.py`, mirroring existing
`tests/test_admin_login_*.py` conventions — same settings fixtures, same mocking-at-the-`oidc`-
module-boundary style used in `tests/test_admin_login_views.py`)

- `login` in cookie mode sets the signed state cookie (not `request.session`), with
  `HttpOnly`/`Secure`/`SameSite` matching settings; `request.session` is untouched/empty.
- `callback` in cookie mode: valid state cookie + mocked `exchange_code` + valid access token →
  sets `ACCESS_COOKIE_NAME` with `max_age` derived from the token's `exp`, deletes the state
  cookie, redirects to `next`, does **not** call `django_login` (patch and assert not called).
- `callback`: missing/tampered/expired state cookie → 400, same message as session mode.
- `callback`: role gate still rejects (403) a login with none of `USER_MODEL_ROLE_FIELD_MAP`'s
  fields `True` — same as session mode, now via the access-token path.
- `callback`: uses `validation.validate_token`, not `oidc.validate_id_token` — assert via mock
  which one gets called.
- `KeycloakAdminCookieMiddleware`: no cookie → no-op, `request.user` unchanged.
- `KeycloakAdminCookieMiddleware`: valid cookie → `request.user` becomes the resolved user; assert
  `resolve_user` (not a reimplementation) was the thing called.
- `KeycloakAdminCookieMiddleware`: expired/invalid/tampered token in cookie → `request.user` stays
  whatever `AuthenticationMiddleware` set (Anonymous), no exception raised.
- `KeycloakAdminCookieMiddleware`: `COOKIE_MODE=False` → no-op even if the cookie happens to be
  present (defense in depth against a stale cookie after a config rollback).
- `logout` in cookie mode: deletes the access cookie, does not call `django_logout`; with
  `LOGOUT_END_SESSION=True`, still redirects through `end_session_endpoint` as today.
- System check: `COOKIE_MODE=True`, `ACCESS_COOKIE_SECURE=False`, `DEBUG=False` → warning fires.
- Zero DB queries when the cookie is absent (same discipline as the DRF path's
  `django_assert_num_queries(0)` test) — a missing cookie must not touch the database at all.

## 7. E2E tests (extend `e2e/test_admin_login.py`, or a sibling `e2e/test_admin_login_cookie.py`
if that reads cleaner — your call)

Use the **`frontend`** client from `e2e/keycloak/realm-test.json` (not `django-admin`) — this is
the whole point being proven end-to-end: the admin flow working against the SPA's own client.

**Realm fixture change required:** `frontend`'s `redirectUris` is currently
`["http://localhost:5173/*"]`, which won't match the Django `live_server` fixture's dynamic
`localhost:<port>`. Add a permissive entry the same way the existing `django-admin` client already
does it in this same file (`"http://localhost:*"`) — don't invent a new pattern, copy the proven
one.

Scenarios:

- Full redirect dance against real Keycloak using `frontend`'s PKCE flow (`directAccessGrantsEnabled`
  is already on for `frontend` in the test realm, same trick other e2e tests use to skip a real
  browser — reuse it: obtain a code via the same mechanism `test_admin_login.py` already uses, or
  if PKCE realistically requires the browser-redirect leg, drive `login`→(mocked redirect
  capture)→real Keycloak token endpoint call for `callback`, consistent with how the existing
  session-mode e2e test splits "code paths that talk to Keycloak" from "view-level HTTP flow" per
  that file's own module docstring). The output must be a real signed access token from the real
  realm, validated by the real `validate_token`.
- alice (has the mapped admin role) completes the flow → `ACCESS_COOKIE_NAME` cookie set, a
  subsequent request to an admin page with that cookie resolves `request.user` to alice with the
  right `is_staff`/`is_superuser`.
- bob (no mapped role) completes the Keycloak login but gets 403 at the role gate — no cookie set.
- A request with a cookie holding an **expired** real token (use the realm's short-lived-token
  client pattern, same as `frontend-short` elsewhere in this repo, or just wait out a short
  lifespan) → middleware leaves the request anonymous, admin's permission check redirects back
  into `login`.
- Measure the real encoded access token length from this exact realm/client and assert it's
  comfortably under the size budget called out in §1 — this is the empirical check that section
  asked for; put the number in a comment so it's not silently invalidated by a future realm change.

## 8. README additions

Under "Django admin login," add a subsection "Cookie mode (optional)" covering:

- When to use this over the default session mode (wants a fully stateless admin surface; doesn't
  want a second Keycloak client).
- Settings table (§3).
- The one Keycloak checklist difference: add the admin's callback URL to the **frontend** client's
  Valid Redirect URIs, no second client needed.
- Explicit callouts, taken from §1: no background refresh (re-auth is a full IdP redirect, expected
  to be invisible via Keycloak's own SSO cookie); `django.contrib.sessions` can stay installed for
  admin's other features, it's just not used for identity; shared logout with the frontend is
  intentional; cookie size is the implementer's responsibility to verify against their own realm's
  token size if they add many roles/scopes.

## 9. CHANGELOG

New `[Unreleased]` → `### Added` entry: *"Optional `COOKIE_MODE` for `admin_login`: authenticates
Django admin from the same Keycloak access token the frontend already uses, stored in a cookie and
re-validated on every request via the existing stateless core — no Django session, no second
Keycloak client, consistent with the rest of the library's stateless design. Existing session mode
is unchanged and remains the default."*

## Phases & acceptance criteria

1. **Feasibility check** — obtain a real token from the test realm's `frontend` client, measure
   its size, confirm against §1's budget. Stop and report if it doesn't fit. This phase produces
   no code.
2. **Settings + checks** — §3, with unit tests for the new system check. `mypy --strict` clean.
3. **Views + middleware** — §4.1–4.4, §4.3's new file. Session-mode behavior byte-for-byte
   unchanged (diff the existing tests: zero changes needed to pass).
4. **Unit tests** — §6 complete, coverage ≥ 90% on the new code.
5. **Realm fixture + e2e** — §7, including the `frontend` `redirectUris` addition.
6. **Docs** — README §8 and CHANGELOG §9.

Out of scope for this task: removing the session mode, background token refresh for cookie mode,
cookie chunking for oversized tokens, any change to `django.contrib.messages` storage, Django
Channels.
