"""
Searchable Encrypted Fields with separate n-gram index tables.

This module provides SearchableEncryptedTextField that wraps django-crypto-fields
and adds full substring search capabilities using separate n-gram index tables.

Architecture:
- Each field gets its own n-gram index table
- Each n-gram is stored as a separate row (not concatenated)
- Lookups use JOINs against the index table
- Automatically maintained via Django signals

Example:
    class User(models.Model):
        email = SearchableEncryptedTextField()

    # Creates table: app_user_email_ngrams with columns:
    # - id (PK)
    # - user_id (FK to User)
    # - ngram_hash (indexed)

    # Enables queries like:
    User.objects.filter(email__contains='@example.com')
"""

from django.apps import apps
from django.db import connection, models
from django.db.models import Lookup, Q
from django.db.models.signals import post_delete, post_save
from django_crypto_fields.fields import EncryptedTextField

from .encryption import SearchableIndexManager


class NGramIndexTable:
    """
    Manages separate n-gram index tables for searchable encrypted fields.

    Each SearchableEncryptedTextField gets its own table for storing
    n-gram hashes, enabling efficient substring searches on encrypted data.
    """

    @staticmethod
    def get_table_name(model_name: str, field_name: str) -> str:
        """
        Get the n-gram index table name for a field.

        Args:
            model_name: Full model name (app_label.ModelName)
            field_name: Field name

        Returns:
            Table name in format: app_modellower_fieldname_ngrams
        """
        app_label, model = model_name.split('.')
        table_name = f"{app_label}_{model.lower()}_{field_name}_ngrams"
        return table_name

    @staticmethod
    def get_foreign_key_column(model_name: str) -> str:
        """
        Get the foreign key column name for the parent model.

        Args:
            model_name: Full model name (app_label.ModelName)

        Returns:
            Column name in format: modellower_id
        """
        _, model = model_name.split('.')
        return f"{model.lower()}_id"

    @classmethod
    def create_table(cls, model_name: str, field_name: str) -> None:
        """
        Create the n-gram index table for a field if it doesn't exist.

        Args:
            model_name: Full model name (app_label.ModelName)
            field_name: Field name
        """
        table_name = cls.get_table_name(model_name, field_name)
        fk_column = cls.get_foreign_key_column(model_name)

        # Get the model to extract the primary key field info
        app_label, model = model_name.split('.')
        model_class = apps.get_model(app_label, model)

        with connection.cursor() as cursor:
            # Check if table exists using database-agnostic method
            try:
                table_exists = table_name in connection.introspection.table_names()
            except Exception:
                # If introspection fails (e.g., during migrations), assume table doesn't exist
                table_exists = False

            if not table_exists:
                # Create the n-gram index table
                parent_table = model_class._meta.db_table

                # Use database-specific syntax for primary key
                if connection.vendor == 'postgresql':
                    pk_definition = "id SERIAL PRIMARY KEY"
                elif connection.vendor == 'sqlite':
                    pk_definition = "id INTEGER PRIMARY KEY AUTOINCREMENT"
                else:
                    pk_definition = "id INTEGER PRIMARY KEY AUTO_INCREMENT"

                cursor.execute(f"""
                    CREATE TABLE {table_name} (
                        {pk_definition},
                        {fk_column} INTEGER NOT NULL,
                        ngram_hash VARCHAR(64) NOT NULL,
                        FOREIGN KEY ({fk_column}) REFERENCES {parent_table}(id) ON DELETE CASCADE
                    )
                """)

                # Create index on ngram_hash for fast lookups
                cursor.execute(f"""
                    CREATE INDEX idx_{table_name}_ngram
                    ON {table_name}(ngram_hash)
                """)

                # Create index on foreign key for efficient joins
                cursor.execute(f"""
                    CREATE INDEX idx_{table_name}_fk
                    ON {table_name}({fk_column})
                """)

    @classmethod
    def index_value(cls, model_instance: models.Model, field_name: str, value: str) -> None:
        """
        Generate and store n-gram indexes for a field value.

        Args:
            model_instance: The model instance
            field_name: Field name to index
            value: The plaintext value to index
        """
        if not value:
            return

        # Get table and column names
        model_name = f"{model_instance._meta.app_label}.{model_instance._meta.object_name}"
        table_name = cls.get_table_name(model_name, field_name)
        fk_column = cls.get_foreign_key_column(model_name)

        # Clear existing indexes for this record
        cls.clear_indexes(model_instance, field_name)

        # Generate n-grams and hash them
        ngrams = SearchableIndexManager.generate_ngrams(value)
        hashed_ngrams = [SearchableIndexManager.hash_ngram(ngram) for ngram in ngrams]

        # Insert n-gram hashes into the index table
        if hashed_ngrams:
            with connection.cursor() as cursor:
                # Prepare values for bulk insert
                values = ', '.join([
                    f"({model_instance.pk}, '{ngram_hash}')"
                    for ngram_hash in hashed_ngrams
                ])

                cursor.execute(f"""
                    INSERT INTO {table_name} ({fk_column}, ngram_hash)
                    VALUES {values}
                """)

    @classmethod
    def clear_indexes(cls, model_instance: models.Model, field_name: str) -> None:
        """
        Clear all n-gram indexes for a field on a model instance.

        Args:
            model_instance: The model instance
            field_name: Field name to clear indexes for
        """
        model_name = f"{model_instance._meta.app_label}.{model_instance._meta.object_name}"
        table_name = cls.get_table_name(model_name, field_name)
        fk_column = cls.get_foreign_key_column(model_name)

        with connection.cursor() as cursor:
            cursor.execute(f"""
                DELETE FROM {table_name}
                WHERE {fk_column} = %s
            """, [model_instance.pk])

    @classmethod
    def search(cls, model_class: type[models.Model], field_name: str, search_term: str) -> Q:
        """
        Generate a Q object for searching n-gram indexes.

        Args:
            model_class: The model class to search
            field_name: Field name to search
            search_term: The search term

        Returns:
            Q object that can be used in a filter
        """
        model_name = f"{model_class._meta.app_label}.{model_class._meta.object_name}"
        table_name = cls.get_table_name(model_name, field_name)
        fk_column = cls.get_foreign_key_column(model_name)
        parent_table = model_class._meta.db_table

        # Generate search tokens (hashed n-grams)
        search_tokens = SearchableIndexManager.create_search_tokens(search_term)

        if not search_tokens:
            return Q(pk__in=[])  # No valid search tokens, return empty queryset

        # Build SQL for subquery using n-gram table
        # Returns IDs of parent records that have matching n-grams
        token_conditions = " AND ".join([
            f"ngram_hash = '{token}'"
            for token in search_tokens
        ])

        sql = f"""
            SELECT DISTINCT {fk_column}
            FROM {table_name}
            WHERE {token_conditions}
        """

        # Use raw SQL in a Q object
        return Q(pk__in=models.RawSQL(sql, []))


class SearchableEncryptedTextField(EncryptedTextField):
    """
    An EncryptedTextField wrapper with full substring search support.

    Wraps django-crypto-fields EncryptedTextField and adds n-gram based
    searching using separate index tables.

    Features:
    - Full encryption via django-crypto-fields
    - Substring search with __contains and __icontains
    - Separate n-gram index table per field
    - Automatic index maintenance via signals

    Usage:
        class User(models.Model):
            email = SearchableEncryptedTextField()
            notes = SearchableEncryptedTextField(blank=True, null=True)

        # All queries work on encrypted data:
        User.objects.filter(email__contains='@example.com')
        User.objects.filter(notes__icontains='important')

    Implementation:
    - Creates separate table: {app}_{model}_{field}_ngrams
    - Stores each n-gram hash as a separate row
    - Uses JOINs for efficient searching
    - Automatically maintained on save/delete
    """

    description = "Searchable encrypted text field with separate n-gram index table"

    def __init__(self, *args, **kwargs):
        """Initialize the field and track metadata for index table creation."""
        super().__init__(*args, **kwargs)
        self._searchable_field = True

    def contribute_to_class(self, cls, name, **kwargs):
        """
        Register the field with the model and set up index table.

        This is called when the field is added to a model class.
        It sets up the n-gram index table and registers signal handlers.
        """
        super().contribute_to_class(cls, name, **kwargs)

        # Create the n-gram index table (deferred to avoid migration issues)
        # Table creation happens at runtime when first accessed

        # Register signal handlers for this specific field
        self._register_signals(cls, name)

    def _register_signals(self, model_class: type[models.Model], field_name: str):
        """
        Register Django signals to maintain n-gram indexes.

        Args:
            model_class: The model class this field belongs to
            field_name: The name of this field
        """
        # Create a unique dispatch_uid to avoid duplicate signal handlers
        dispatch_uid = f"searchable_encrypted_{model_class._meta.label}_{field_name}"

        def handle_post_save(sender, instance, created, **kwargs):
            """Handle post_save signal to update n-gram indexes."""
            try:
                # Ensure table exists
                model_name = f"{sender._meta.app_label}.{sender._meta.object_name}"
                NGramIndexTable.create_table(model_name, field_name)

                # Get the field value (plaintext)
                value = getattr(instance, field_name, None)

                if value:
                    # Index the value
                    NGramIndexTable.index_value(instance, field_name, value)
            except Exception:
                # Silently fail during migrations or when tables don't exist
                pass

        def handle_post_delete(sender, instance, **kwargs):
            """Handle post_delete signal to clean up n-gram indexes."""
            try:
                NGramIndexTable.clear_indexes(instance, field_name)
            except Exception:
                # Silently fail during migrations or when tables don't exist
                pass

        # Connect signals with unique dispatch_uid
        post_save.connect(
            handle_post_save,
            sender=model_class,
            dispatch_uid=f"{dispatch_uid}_save",
            weak=False
        )

        post_delete.connect(
            handle_post_delete,
            sender=model_class,
            dispatch_uid=f"{dispatch_uid}_delete",
            weak=False
        )

    def get_prep_lookup(self, lookup_type, value):
        """
        Prepare the value for database lookup.

        For searchable lookups (contains, icontains), we bypass encryption
        entirely and return the plaintext value.
        """
        if lookup_type in ('contains', 'icontains'):
            # Return plaintext - don't encrypt for search
            return value
        return super().get_prep_lookup(lookup_type, value)

    def get_db_prep_lookup(self, lookup_type, value, connection, prepared=False):
        """
        Prepare the value for database lookup (database-specific).

        For searchable lookups, we bypass encryption and return plaintext.
        """
        if lookup_type in ('contains', 'icontains'):
            # Return plaintext without encryption
            return value
        return super().get_db_prep_lookup(lookup_type, value, connection, prepared)

# Custom lookups for SearchableEncryptedTextField


class SearchableContains(Lookup):
    """
    Custom CONTAINS lookup that uses the n-gram index table.

    Generates a subquery that joins against the n-gram table
    to find matching records.
    """
    lookup_name = 'contains'

    def __init__(self, lhs, rhs):
        """Store the plaintext value before Django processes it."""
        # Store plaintext BEFORE parent class processes it (and potentially encrypts it)
        self._plaintext_rhs = str(rhs) if rhs else ""
        super().__init__(lhs, rhs)

    def as_sql(self, compiler, connection):
        """
        Generate SQL using the n-gram index table.

        Returns SQL that performs a subquery JOIN against the n-gram table.
        """
        lhs, lhs_params = self.process_lhs(compiler, connection)

        # Get the model and field info
        field = self.lhs.field
        model_class = self.lhs.target.model
        field_name = field.name

        # Use the plaintext value we stored in __init__
        search_term = self._plaintext_rhs

        if not search_term:
            return "1=0", ()

        # Generate search tokens (lowercase n-grams)
        search_tokens = SearchableIndexManager.create_search_tokens(search_term.lower())

        # For substring search, remove the full-text n-gram (if present and longer than n-gram size)
        # The full-text n-gram is useful for exact matches, but breaks substring matching
        # However, for short search terms (length <= n-gram size), keep it as it's the only n-gram
        search_term_lower = search_term.lower().strip()
        if len(search_term_lower) > SearchableIndexManager.NGRAM_SIZE:
            full_text_hash = SearchableIndexManager.hash_ngram(search_term_lower)
            search_tokens = {token for token in search_tokens if token != full_text_hash}

        if not search_tokens:
            return "1=0", ()

        # Build the subquery SQL
        model_name = f"{model_class._meta.app_label}.{model_class._meta.object_name}"
        table_name = NGramIndexTable.get_table_name(model_name, field_name)
        fk_column = NGramIndexTable.get_foreign_key_column(model_name)
        parent_table = model_class._meta.db_table

        # Get the primary key column name (usually 'id')
        pk_column = model_class._meta.pk.column

        # Create parameterized query for tokens
        params = list(search_tokens)
        num_tokens = len(params)

        # Build IN clause with properly quoted string literals
        # Note: Using string formatting here is safe because hash values are generated by our code (SHA-256 hex)
        token_list = ', '.join([f"'{token}'" for token in params])

        # Generate SQL that requires ALL tokens to match (AND logic)
        # Uses GROUP BY and HAVING to ensure all search n-grams are present
        # fmt: off
        sql = (
            f'"{parent_table}"."{pk_column}" IN ('
            f'SELECT "{fk_column}" '
            f'FROM "{table_name}" '
            f'WHERE "ngram_hash" IN ({token_list}) '
            f'GROUP BY "{fk_column}" '
            f'HAVING COUNT(DISTINCT "ngram_hash") = {num_tokens}'
            f')'
        )
        # fmt: on

        return sql, ()


class SearchableIContains(SearchableContains):
    """
    Case-insensitive CONTAINS lookup.

    Since n-grams are already lowercase-normalized, this behaves
    identically to SearchableContains.
    """
    lookup_name = 'icontains'

    def __init__(self, lhs, rhs):
        """Store the plaintext value before Django processes it."""
        # Inherit parent's __init__ which stores plaintext
        super().__init__(lhs, rhs)


# Register the custom lookups
SearchableEncryptedTextField.register_lookup(SearchableContains)
SearchableEncryptedTextField.register_lookup(SearchableIContains)
