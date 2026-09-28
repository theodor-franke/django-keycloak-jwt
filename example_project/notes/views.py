from typing import ClassVar

from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from django_keycloak_jwt.drf.permissions import HasClientRole, HasRealmRole

from .models import Note
from .serializers import NoteSerializer


class PublicView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [AllowAny]

    def get(self, request: Request) -> Response:
        return Response({"message": "public"})


class MeView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        user = request.user
        # USER_MODEL_ENABLED is on in this project, so request.user is the
        # resolved AUTH_USER_MODEL row; claim/role helpers live on .keycloak.
        principal = user.keycloak
        return Response(
            {
                "sub": principal.sub,
                "username": user.username,
                "email": user.email,
                "realm_roles": sorted(principal.realm_roles),
                "client_roles": sorted(principal.client_roles()),
            }
        )


class StaffView(APIView):
    permission_classes: ClassVar[list[type[BasePermission]]] = [HasRealmRole.of("staff")]

    def get(self, request: Request) -> Response:
        return Response({"message": "staff-only"})


class NoteListCreateView(ListCreateAPIView):
    serializer_class = NoteSerializer

    def get_permissions(self) -> list[BasePermission]:
        if self.request.method == "POST":
            return [HasClientRole.of("editor")()]
        return [IsAuthenticated()]

    def get_queryset(self):
        return Note.objects.filter(owner_sub=self.request.user.keycloak.sub)

    def perform_create(self, serializer: NoteSerializer) -> None:
        serializer.save(owner_sub=self.request.user.keycloak.sub)
