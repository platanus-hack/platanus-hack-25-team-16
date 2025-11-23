from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom UserAdmin for the encrypted User model.

    Shows both encrypted and non-encrypted fields in the admin interface.
    Encrypted fields are automatically decrypted when displayed.
    """

    # Fields to display in the list view
    list_display = ['first_name', 'last_name', 'email']

    list_filter = []

    search_fields = ["first_name", "last_name", "email"]

    ordering = ["first_name", "last_name"]
