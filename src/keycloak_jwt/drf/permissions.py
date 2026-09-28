"""DRF permission classes for Keycloak realm and client roles."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rest_framework.permissions import BasePermission

from ..principal import KeycloakUser

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView


class HasRealmRole(BasePermission):
    """Grants access if the user has every role in ``required_roles``.

    Use :meth:`of` for a one-off subclass rather than setting the class
    attribute directly::

        permission_classes = [HasRealmRole.of("staff")]
    """

    required_roles: ClassVar[tuple[str, ...]] = ()

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        if not isinstance(user, KeycloakUser):
            return False
        return all(user.has_realm_role(role) for role in self.required_roles)

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
        user = request.user
        if not isinstance(user, KeycloakUser):
            return False
        client_roles = user.client_roles(self.client_id)
        return all(role in client_roles for role in self.required_roles)

    @classmethod
    def of(cls, *roles: str, client_id: str | None = None) -> type[HasClientRole]:
        return type(
            f"{cls.__name__}_{'_'.join(roles)}",
            (cls,),
            {"required_roles": tuple(roles), "client_id": client_id},
        )
