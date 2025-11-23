"""
Custom User Model with Encrypted Fields

Demonstrates both searchable and non-searchable encrypted fields
for ISO27001 A.10.1 compliance.
"""


from django.contrib.auth.models import AbstractUser
from django_crypto_fields import fields as crypto_fields

from data_protection.fields import SearchableEncryptedTextField


class User(AbstractUser):
    first_name = SearchableEncryptedTextField(
        max_length=150,
        blank=True,
        help_text="First name (encrypted, with search)",
    )

    last_name = crypto_fields.EncryptedCharField(
        max_length=150,
        blank=True,
        help_text="Last name (encrypted, no search)"
    )
