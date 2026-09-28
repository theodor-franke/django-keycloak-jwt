"""Optional drf-spectacular integration.

Only imported by callers that use drf-spectacular; nothing else in this
package imports this module, so the package works fine without
``drf-spectacular`` installed. When it *is* installed, importing this
module registers the ``KeycloakJWTAuthentication`` -> HTTP bearer/JWT
security scheme mapping.
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class KeycloakJWTScheme(OpenApiAuthenticationExtension):  # type: ignore[no-untyped-call]
    target_class = "django_keycloak_jwt.drf.authentication.KeycloakJWTAuthentication"
    name = "KeycloakJWT"

    def get_security_definition(self, auto_schema: Any) -> dict[str, str]:
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
