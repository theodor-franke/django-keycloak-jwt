from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """AUTH_USER_MODEL for this example project.

    ``keycloak_sub`` is the field ``USER_MODEL_LOOKUP_FIELD`` is matched
    against (see ``KEYCLOAK_JWT`` in settings.py) -- a dedicated field
    rather than reusing ``username``/``email``, since Keycloak's ``sub`` is
    the only claim guaranteed stable across a KC-side rename.
    """

    keycloak_sub = models.UUIDField(unique=True, null=True, blank=True, db_index=True)
