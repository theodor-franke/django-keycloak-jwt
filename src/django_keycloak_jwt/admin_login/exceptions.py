"""Exceptions specific to the admin OIDC login flow."""

from __future__ import annotations


class TokenExchangeFailed(Exception):
    """Keycloak's token endpoint call failed or returned an unusable response."""


class AdminAccessDenied(Exception):
    """The authenticated Keycloak user holds none of the required admin roles."""
