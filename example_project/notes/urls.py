from django.urls import path

from .views import MeView, NoteListCreateView, PublicView, StaffView

urlpatterns = [
    path("public/", PublicView.as_view(), name="public"),
    path("me/", MeView.as_view(), name="me"),
    path("notes/", NoteListCreateView.as_view(), name="notes"),
    path("staff/", StaffView.as_view(), name="staff"),
]
