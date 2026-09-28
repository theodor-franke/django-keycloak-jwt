"""Minimal DRF views used only by the test suite."""

from __future__ import annotations

from typing import ClassVar

from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from django_keycloak_jwt.drf.permissions import HasClientRole, HasRealmRole


class EchoUserView(APIView):
    def get(self, request: Request) -> Response:
        user = request.user
        return Response(
            {
                "authenticated": bool(user.is_authenticated),
                "sub": getattr(user, "sub", None),
                "username": getattr(user, "username", None),
            }
        )


class RequireAuthenticatedView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        return Response({"ok": True})


class RequireRealmStaffView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [HasRealmRole.of("staff")]

    def get(self, request: Request) -> Response:
        return Response({"ok": True})


class RequireClientEditorView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [HasClientRole.of("editor")]

    def get(self, request: Request) -> Response:
        return Response({"ok": True})


class RequireClientEditorExplicitClientView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [
        HasClientRole.of("editor", client_id="other-api")
    ]

    def get(self, request: Request) -> Response:
        return Response({"ok": True})
