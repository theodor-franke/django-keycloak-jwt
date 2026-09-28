from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = (
        *DjangoUserAdmin.fieldsets,
        ("Keycloak", {"fields": ("keycloak_sub",)}),
    )
    list_display = (*DjangoUserAdmin.list_display, "keycloak_sub")
    readonly_fields = (*DjangoUserAdmin.readonly_fields, "keycloak_sub")
