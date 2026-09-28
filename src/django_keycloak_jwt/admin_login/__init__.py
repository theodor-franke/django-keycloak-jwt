"""Optional Keycloak OIDC login flow for the Django admin.

Not installed by default and entirely separate from the core resource-server
authentication path: nothing here runs unless
``"django_keycloak_jwt.admin_login"`` is added to ``INSTALLED_APPS``. Where
the core package validates a bearer token already held by the caller, this
module drives a full Authorization Code + PKCE redirect to obtain one for a
browser, then starts a normal Django session.

See the README's "Django admin login" section for setup instructions.
"""

from __future__ import annotations
