from django.db import models


class Note(models.Model):
    owner_sub = models.UUIDField(db_index=True)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"Note({self.pk}, owner={self.owner_sub})"
