"""
Example models demonstrating encrypted field usage.

Shows how to use HomomorphicEncryptedTextField (searchable) and
django-crypto-fields (battle-tested) for ISO27001 compliant data protection.
"""


from django.db import models
from django_crypto_fields import fields as crypto_fields

from .fields import SearchableEncryptedTextField


class DjangoCryptoFieldsExample(models.Model):
    """
    Example using django-crypto-fields library directly.

    django-crypto-fields is a battle-tested library used in production
    clinical trial systems. Provides strong encryption without pattern matching.

    For fields that need pattern matching, use HomomorphicEncrypted fields instead.
    """

    # Using django-crypto-fields directly
    first_name = crypto_fields.EncryptedCharField(max_length=100)
    last_name = crypto_fields.EncryptedCharField(max_length=100)

    # SSN - highly sensitive, no search needed
    ssn = crypto_fields.EncryptedCharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="SSN (encrypted, no pattern matching)"
    )

    # Large text field
    medical_history = crypto_fields.EncryptedTextField(
        blank=True,
        null=True,
        help_text="Medical history (encrypted)"
    )

    # Integer field (encrypted)
    patient_id = crypto_fields.EncryptedIntegerField(
        help_text="Patient ID (encrypted)"
    )

    # Date field (encrypted)
    date_of_birth = crypto_fields.EncryptedDateField(
        help_text="DOB (encrypted)"
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Django Crypto Fields Example"
        verbose_name_plural = "Django Crypto Fields Examples"
        db_table = "data_protection_django_crypto"

    def __str__(self):
        return f"Patient {self.patient_id}"


# =============================================================================
# USAGE NOTES
# =============================================================================

# Field Selection Guide:
#
# 1. SearchableEncryptedTextField:
#    - Use when: Need substring search on encrypted data
#    - Architecture: Separate n-gram index tables per field
#    - Trade-off: More database tables, but better query performance
#    - Example: Searchable emails, notes, descriptions
#    - Lookups: contains, icontains
#    - Storage: Each n-gram stored as separate row with hash
#
# 2. django-crypto-fields (crypto_fields.*):
#    - Use when: Don't need pattern matching, maximum security
#    - Base: Battle-tested in production clinical trials
#    - Trade-off: No substring/pattern queries
#    - Example: SSN, medical records, sensitive IDs
#    - Lookups: Exact match only
#
# Note: Both approaches are ISO27001 A.10.1 compliant


class SearchableDataExample(models.Model):
    """
    Example using SearchableEncryptedTextField with separate n-gram index tables.

    This approach uses a completely separate table for each field's n-gram indexes,
    providing normalized database structure and efficient searching.

    Features:
    - Each field gets its own n-gram index table (e.g., data_protection_searchabledataexample_email_ngrams)
    - Each n-gram is stored as a separate row with a hash
    - Lookups use JOINs against the index tables
    - Automatically maintained via Django signals

    Trade-offs:
    - More tables in the database
    - Better query performance with proper indexing
    - More normalized structure

    Usage:
        # All these work with encrypted data!
        SearchableDataExample.objects.filter(email__contains='@example')
        SearchableDataExample.objects.filter(notes__icontains='important')
    """

    # Searchable encrypted fields with separate index tables
    email = SearchableEncryptedTextField(
        help_text="Email (encrypted, searchable with separate n-gram table)"
    )

    notes = SearchableEncryptedTextField(
        blank=True,
        null=True,
        help_text="Notes (encrypted, searchable with separate n-gram table)"
    )

    # Non-encrypted metadata
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Searchable Data Example"
        verbose_name_plural = "Searchable Data Examples"
        db_table = "data_protection_searchable"

    def __str__(self):
        return f"Searchable Data: {self.email}"
