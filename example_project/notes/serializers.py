from typing import ClassVar

from rest_framework import serializers

from .models import Note


class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields: ClassVar[list[str]] = ["id", "owner_sub", "text", "created_at"]
        read_only_fields: ClassVar[list[str]] = ["id", "owner_sub", "created_at"]
