"""The claims-backed request principal.

``KeycloakUser`` is deliberately not a Django model and not an
``AbstractBaseUser`` subclass: there is no database-backed user, and the
authentication path performs no DB queries. To associate application data
with a user, store their ``sub`` claim (e.g. in an ``owner_sub`` field),
not a foreign key to ``auth.User``.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .conf import get_settings


class KeycloakUser:
    """A DRF-compatible principal backed by verified Keycloak JWT claims."""

    is_authenticated = True
    is_anonymous = False
    is_active = True
    is_staff = False
    is_superuser = False

    def __init__(self, claims: Mapping[str, Any]) -> None:
        self.claims: Mapping[str, Any] = MappingProxyType(dict(claims))

    @property
    def sub(self) -> str:
        return str(self.claims.get("sub", ""))

    @property
    def pk(self) -> str:
        return self.sub

    @property
    def id(self) -> str:
        return self.sub

    @property
    def username(self) -> str:
        value = self.claims.get("preferred_username")
        return str(value) if value else self.sub

    @property
    def email(self) -> str | None:
        value = self.claims.get("email")
        return str(value) if value is not None else None

    @property
    def given_name(self) -> str | None:
        value = self.claims.get("given_name")
        return str(value) if value is not None else None

    @property
    def family_name(self) -> str | None:
        value = self.claims.get("family_name")
        return str(value) if value is not None else None

    @property
    def azp(self) -> str | None:
        value = self.claims.get("azp")
        return str(value) if value is not None else None

    @property
    def realm_roles(self) -> frozenset[str]:
        realm_access = self.claims.get("realm_access")
        if not isinstance(realm_access, Mapping):
            return frozenset()
        roles = realm_access.get("roles")
        if not isinstance(roles, list):
            return frozenset()
        return frozenset(str(role) for role in roles)

    def client_roles(self, client_id: str | None = None) -> frozenset[str]:
        resolved_client_id = client_id or get_settings().ROLE_CLIENT
        if not resolved_client_id:
            return frozenset()
        resource_access = self.claims.get("resource_access")
        if not isinstance(resource_access, Mapping):
            return frozenset()
        client_entry = resource_access.get(resolved_client_id)
        if not isinstance(client_entry, Mapping):
            return frozenset()
        roles = client_entry.get("roles")
        if not isinstance(roles, list):
            return frozenset()
        return frozenset(str(role) for role in roles)

    def has_realm_role(self, role: str) -> bool:
        return role in self.realm_roles

    def has_client_role(self, role: str, client_id: str | None = None) -> bool:
        return role in self.client_roles(client_id)

    def get_username(self) -> str:
        return self.username

    def has_perm(self, perm: str, obj: object | None = None) -> bool:
        return False

    def has_perms(self, perm_list: Any, obj: object | None = None) -> bool:
        return False

    def has_module_perms(self, app_label: str) -> bool:
        return False

    def __str__(self) -> str:
        return self.username

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeycloakUser):
            return NotImplemented
        return self.sub == other.sub

    def __hash__(self) -> int:
        return hash(self.sub)
