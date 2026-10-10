"""Optional caching resolution of a local ``AUTH_USER_MODEL`` row from
verified Keycloak claims.

Disabled by default (``KEYCLOAK_JWT['USER_MODEL_ENABLED']``): the package's
authentication path performs no DB queries unless this is turned on. When
enabled, :func:`resolve_user` fetches (and optionally auto-provisions) the
local user row matching a claim value, caches the instance in Django's
default cache for ``USER_MODEL_CACHE_TTL`` seconds, and keeps it fresh via
``post_save``/``post_delete`` signal invalidation (wired up in
:class:`~django_keycloak_jwt.apps.KeycloakJWTConfig.ready`).

``USER_MODEL_ROLE_FIELD_MAP`` fields are the exception to that TTL: on every
call, cache hit or miss, they're re-diffed against *this request's* claims
(not just at cache-miss time), so a role revoked/granted in Keycloak takes
effect on the very next request rather than waiting out the TTL. This only
costs a DB write when a mapped field actually flips -- a no-op diff (the
common case) stays cache-speed.

A process-shared cache backend (e.g. Redis or Memcached) is required for the
invalidation signal to be visible across worker processes — see the
``django_keycloak_jwt.W003`` system check.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.utils.module_loading import import_string

from .conf import KeycloakJWTSettings, get_settings
from .exceptions import TokenInvalid, UserNotFound
from .principal import KeycloakUser

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser

CACHE_KEY_PREFIX = "django_keycloak_jwt:user_model"

#: Upper bound on ``_1``, ``_2``, ... suffix attempts when the username a new
#: user is provisioned with collides with an existing row. Guards against an
#: infinite loop if the IntegrityError turns out to be unrelated (e.g. some
#: other unique column clashing), in which case the original error is
#: re-raised once the budget is exhausted.
_MAX_USERNAME_SUFFIX_ATTEMPTS = 1000


def resolve_user(claims: dict[str, Any]) -> AbstractBaseUser:
    """Resolve, cache, and return the local user for *claims*.

    Only meaningful when ``USER_MODEL_ENABLED`` is True. *claims* must
    already be verified (i.e. the return value of
    :func:`django_keycloak_jwt.validation.validate_token`).

    Raises :class:`~django_keycloak_jwt.exceptions.TokenInvalid` if the
    configured lookup claim is absent from *claims*, and
    :class:`~django_keycloak_jwt.exceptions.UserNotFound` if no local row
    matches and ``USER_MODEL_AUTO_CREATE`` is False.

    The returned instance always carries a ``.keycloak`` attribute — a
    ``USER_CLASS`` instance wrapping *claims* — so role/claim helpers stay
    available alongside the real model instance.
    """
    settings = get_settings()
    lookup_value = claims.get(settings.USER_MODEL_LOOKUP_CLAIM)
    if lookup_value is None:
        raise TokenInvalid("missing_user_model_lookup_claim")

    key = _cache_key(lookup_value)
    user: AbstractBaseUser | None = cache.get(key)
    if user is None:
        user = _fetch_or_create(claims, lookup_value, settings)
        cache.set(key, user, settings.USER_MODEL_CACHE_TTL)
    elif _sync_role_fields(user, claims, settings):
        # A mapped role flipped since this row was cached. Re-save just the
        # role columns and refresh the cache entry so the corrected value
        # is what the *next* cache hit compares against -- otherwise every
        # request up to TTL expiry would keep re-diffing against the same
        # stale copy and re-issuing this same write.
        user.save(update_fields=list(settings.USER_MODEL_ROLE_FIELD_MAP.values()))
        cache.set(key, user, settings.USER_MODEL_CACHE_TTL)

    principal_class = import_string(settings.USER_CLASS)
    setattr(user, "keycloak", principal_class(claims))  # noqa: B010
    return user


def invalidate_user_cache(instance: AbstractBaseUser) -> None:
    """Drop the cached entry for *instance*, if caching is enabled.

    Called from ``post_save``/``post_delete`` receivers connected in
    :class:`~django_keycloak_jwt.apps.KeycloakJWTConfig.ready`.
    """
    try:
        settings = get_settings()
    except ImproperlyConfigured:
        return

    if not settings.USER_MODEL_ENABLED or not settings.USER_MODEL_LOOKUP_FIELD:
        return

    lookup_value = getattr(instance, settings.USER_MODEL_LOOKUP_FIELD, None)
    if lookup_value is None:
        return

    cache.delete(_cache_key(lookup_value))


def _cache_key(lookup_value: Any) -> str:
    return f"{CACHE_KEY_PREFIX}:{lookup_value}"


def _fetch_or_create(
    claims: dict[str, Any], lookup_value: Any, settings: KeycloakJWTSettings
) -> AbstractBaseUser:
    model = get_user_model()
    lookup_field = settings.USER_MODEL_LOOKUP_FIELD
    if lookup_field is None:
        raise ImproperlyConfigured(
            "USER_MODEL_LOOKUP_FIELD is required when USER_MODEL_ENABLED is True."
        )
    user = model.objects.filter(**{lookup_field: lookup_value}).first()

    if user is None:
        if not settings.USER_MODEL_AUTO_CREATE:
            raise UserNotFound(
                f"No user with {lookup_field}={lookup_value!r} and USER_MODEL_AUTO_CREATE is False."
            )
        user = model(**{lookup_field: lookup_value})
        _apply_field_map(user, claims, settings)
        _sync_role_fields(user, claims, settings)
        _save_user_deduping_username(user, model)
        return user

    changed = _apply_field_map(user, claims, settings)
    changed = _sync_role_fields(user, claims, settings) or changed
    if changed:
        _save_user_deduping_username(user, model)
    return user


def _save_user_deduping_username(user: AbstractBaseUser, model: type[AbstractBaseUser]) -> None:
    """Save *user* (new or existing), disambiguating a colliding username.

    ``USER_MODEL_LOOKUP_FIELD`` (usually a ``sub``-backed column) is
    confirmed distinct by the caller, but ``USER_MODEL_FIELD_MAP`` commonly
    copies the claims' ``preferred_username`` onto the model's username
    field independently of that lookup -- on both initial creation and
    later re-sync of an existing row. Two different Keycloak subjects can
    end up with the same ``preferred_username`` (renames, realm merges,
    federated identities, ...), which trips the username column's unique
    constraint and would otherwise fail the login outright. Retry with an
    incrementing ``_1``, ``_2``, ... suffix until the save succeeds.
    """
    username_field = getattr(model, "USERNAME_FIELD", None)
    base_username = getattr(user, username_field, None) if username_field else None

    if username_field is None or base_username is None:
        user.save()
        return

    for attempt in range(1, _MAX_USERNAME_SUFFIX_ATTEMPTS + 1):
        try:
            with transaction.atomic():
                user.save()
            return
        except IntegrityError:
            setattr(user, username_field, f"{base_username}_{attempt}")

    user.save()


def _apply_field_map(
    user: AbstractBaseUser, claims: dict[str, Any], settings: KeycloakJWTSettings
) -> bool:
    changed = False
    for claim_name, field_name in settings.USER_MODEL_FIELD_MAP.items():
        value = claims.get(claim_name)
        if value is None:
            continue
        if getattr(user, field_name, None) != value:
            setattr(user, field_name, value)
            changed = True
    return changed


def _sync_role_fields(
    user: AbstractBaseUser, claims: dict[str, Any], settings: KeycloakJWTSettings
) -> bool:
    role_map = settings.USER_MODEL_ROLE_FIELD_MAP
    if not role_map:
        return False

    roles = KeycloakUser(claims).client_roles(settings.ROLE_CLIENT)
    changed = False
    for role_name, field_name in role_map.items():
        desired = role_name in roles
        if getattr(user, field_name) != desired:
            setattr(user, field_name, desired)
            changed = True
    return changed
