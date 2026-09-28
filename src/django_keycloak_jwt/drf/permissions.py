"""DRF permission classes for Keycloak realm and client roles."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rest_framework.permissions import BasePermission

from ..principal import KeycloakUser

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView


def _keycloak_principal(user: object) -> KeycloakUser | None:
    """Return the claims-backed principal for *user*, or ``None``.

    ``user`` is a ``KeycloakUser`` directly by default. When
    ``USER_MODEL_ENABLED`` is on, ``request.user`` is instead the resolved
    ``AUTH_USER_MODEL`` instance and the principal lives on its
    ``.keycloak`` attribute (see ``user_resolution.resolve_user``).
    """
    if isinstance(user, KeycloakUser):
        return user
    principal = getattr(user, "keycloak", None)
    return principal if isinstance(principal, KeycloakUser) else None


class HasRealmRole(BasePermission):
    """Grants access if the user has every role in ``required_roles``.

    Use :meth:`of` for a one-off subclass rather than setting the class
    attribute directly::

        permission_classes = [HasRealmRole.of("staff")]
    """

    required_roles: ClassVar[tuple[str, ...]] = ()

    def has_permission(self, request: Request, view: APIView) -> bool:
        principal = _keycloak_principal(request.user)
        if principal is None:
            return False
        return all(principal.has_realm_role(role) for role in self.required_roles)

    @classmethod
    def of(cls, *roles: str) -> type[HasRealmRole]:
        return type(
            f"{cls.__name__}_{'_'.join(roles)}",
            (cls,),
            {"required_roles": tuple(roles)},
        )


class HasClientRole(BasePermission):
    """Grants access if the user has every role in ``required_roles`` on
    ``client_id`` (or ``KEYCLOAK_JWT['ROLE_CLIENT']`` if unset).

    Use :meth:`of` for a one-off subclass::

        permission_classes = [HasClientRole.of("editor", client_id="api")]
    """

    required_roles: ClassVar[tuple[str, ...]] = ()
    client_id: ClassVar[str | None] = None

    def has_permission(self, request: Request, view: APIView) -> bool:
        principal = _keycloak_principal(request.user)
        if principal is None:
            return False
        client_roles = principal.client_roles(self.client_id)
        return all(role in client_roles for role in self.required_roles)

    @classmethod
    def of(cls, *roles: str, client_id: str | None = None) -> type[HasClientRole]:
        return type(
            f"{cls.__name__}_{'_'.join(roles)}",
            (cls,),
            {"required_roles": tuple(roles), "client_id": client_id},
        )
