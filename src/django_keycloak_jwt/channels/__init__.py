"""Optional Django Channels (WebSocket) integration.

Requires the ``channels`` extra: ``pip install "django-keycloak-jwt[channels]"``.
Entirely separate from the DRF and admin_login paths -- nothing here is
imported by the rest of the package, so it costs nothing for projects that
don't use WebSockets.

See the README's "Django Channels" section for setup instructions.
"""

from __future__ import annotations
