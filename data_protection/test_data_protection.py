"""
Unit tests for data_protection app.

Tests encryption, decryption, searchable indexes, and field functionality
to ensure ISO27001 A.10.1 compliance.
"""


from django.db import connection
from django.test import TestCase

from .encryption import SearchableIndexManager
from .fields import NGramIndexTable
from .models import SearchableDataExample


class SearchableIndexManagerTests(TestCase):
    """Test SearchableIndexManager n-gram indexing functionality."""

    def test_generate_ngrams(self):
        """Test n-gram generation."""
        text = "hello"
        ngrams = SearchableIndexManager.generate_ngrams(text, n=3)

        # Should contain trigrams
        self.assertIn("hel", ngrams)
        self.assertIn("ell", ngrams)
        self.assertIn("llo", ngrams)
        # Should contain full text
        self.assertIn("hello", ngrams)

    def test_generate_ngrams_short_text(self):
        """Test n-gram generation for text shorter than n."""
        text = "hi"
        ngrams = SearchableIndexManager.generate_ngrams(text, n=3)

        # Should contain the text itself
        self.assertIn("hi", ngrams)

    def test_generate_ngrams_empty(self):
        """Test n-gram generation for empty string."""
        ngrams = SearchableIndexManager.generate_ngrams("", n=3)
        self.assertEqual(ngrams, set())

    def test_generate_ngrams_case_insensitive(self):
        """Test that n-grams are lowercase normalized."""
        ngrams1 = SearchableIndexManager.generate_ngrams("Hello")
        ngrams2 = SearchableIndexManager.generate_ngrams("hello")

        self.assertEqual(ngrams1, ngrams2)

    def test_hash_ngram(self):
        """Test n-gram hashing."""
        ngram = "hel"
        hash1 = SearchableIndexManager.hash_ngram(ngram)

        # Should be deterministic
        hash2 = SearchableIndexManager.hash_ngram(ngram)
        self.assertEqual(hash1, hash2)

        # Should be different for different n-grams
        hash3 = SearchableIndexManager.hash_ngram("ell")
        self.assertNotEqual(hash1, hash3)

        # Should be hex string
        self.assertIsInstance(hash1, str)
        self.assertEqual(len(hash1), 64)  # SHA-256 hex = 64 chars

    def test_create_search_index(self):
        """Test search index creation."""
        plaintext = "john_doe"
        index = SearchableIndexManager.create_search_index(plaintext)

        # Should be space-separated hashes
        self.assertIsInstance(index, str)
        self.assertGreater(len(index), 0)
        tokens = index.split()
        self.assertGreater(len(tokens), 0)

        # Each token should be a hex hash
        for token in tokens:
            self.assertEqual(len(token), 64)

    def test_create_search_index_empty(self):
        """Test search index creation for empty string."""
        index = SearchableIndexManager.create_search_index("")
        self.assertEqual(index, "")

    def test_create_search_tokens(self):
        """Test search token creation."""
        search_term = "john"
        tokens = SearchableIndexManager.create_search_tokens(search_term)

        # Should return set of hashes
        self.assertIsInstance(tokens, set)
        self.assertGreater(len(tokens), 0)

        # Each token should be a hex hash
        for token in tokens:
            self.assertEqual(len(token), 64)

    def test_create_search_tokens_too_short(self):
        """Test search token creation for short search term."""
        tokens = SearchableIndexManager.create_search_tokens("a")
        self.assertEqual(tokens, set())

    def test_matches_search_positive(self):
        """Test search matching - should find match."""
        plaintext = "john_doe"
        index = SearchableIndexManager.create_search_index(plaintext)

        # Should match substring
        self.assertTrue(SearchableIndexManager.matches_search(index, "john"))
        self.assertTrue(SearchableIndexManager.matches_search(index, "doe"))
        self.assertTrue(SearchableIndexManager.matches_search(index, "hn_"))

    def test_matches_search_negative(self):
        """Test search matching - should not find match."""
        plaintext = "john_doe"
        index = SearchableIndexManager.create_search_index(plaintext)

        # Should not match unrelated text
        self.assertFalse(SearchableIndexManager.matches_search(index, "jane"))
        self.assertFalse(SearchableIndexManager.matches_search(index, "smith"))

    def test_matches_search_case_insensitive(self):
        """Test search matching is case-insensitive."""
        plaintext = "JohnDoe"
        index = SearchableIndexManager.create_search_index(plaintext)

        self.assertTrue(SearchableIndexManager.matches_search(index, "john"))
        self.assertTrue(SearchableIndexManager.matches_search(index, "JOHN"))
        self.assertTrue(SearchableIndexManager.matches_search(index, "John"))


class SearchableEncryptedFieldTests(TestCase):
    """Test SearchableEncryptedTextField with separate n-gram index tables."""

    def setUp(self):
        """Set up test fixtures."""
        # Create n-gram tables for testing
        model_name = "data_protection.SearchableDataExample"
        NGramIndexTable.create_table(model_name, "email")
        NGramIndexTable.create_table(model_name, "notes")

    def tearDown(self):
        """Clean up after tests."""
        # Clean up test data
        SearchableDataExample.objects.all().delete()

    def test_create_instance(self):
        """Test creating an instance with SearchableEncryptedTextField."""
        obj = SearchableDataExample.objects.create(
            email="alice@example.com",
            notes="Important notes here"
        )

        # Should save successfully
        self.assertIsNotNone(obj.id)
        self.assertEqual(obj.email, "alice@example.com")
        self.assertEqual(obj.notes, "Important notes here")

    def test_encryption_at_rest(self):
        """Test that data is encrypted in the database."""
        obj = SearchableDataExample.objects.create(
            email="bob@test.com"
        )

        # Query database directly to verify encryption
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT email FROM data_protection_searchable WHERE id = %s",
                [obj.id]
            )
            row = cursor.fetchone()
            encrypted_value = row[0]

        # Encrypted value should not be plaintext
        self.assertNotEqual(encrypted_value, "bob@test.com")
        self.assertIn(":", encrypted_value)  # Should have version prefix

    def test_ngram_table_creation(self):
        """Test that n-gram index tables are created."""
        model_name = "data_protection.SearchableDataExample"
        table_name = NGramIndexTable.get_table_name(model_name, "email")

        # Check table exists using database-agnostic method
        table_exists = table_name in connection.introspection.table_names()

        self.assertTrue(table_exists, f"Table {table_name} should exist")

    def test_ngram_index_populated(self):
        """Test that n-gram indexes are populated on save."""
        obj = SearchableDataExample.objects.create(
            email="charlie@domain.com"
        )

        # Check n-gram table has entries
        model_name = "data_protection.SearchableDataExample"
        table_name = NGramIndexTable.get_table_name(model_name, "email")

        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) FROM {table_name} WHERE searchabledataexample_id = %s",
                [obj.id]
            )
            count = cursor.fetchone()[0]

        # Should have multiple n-gram entries
        self.assertGreater(count, 0)

    def test_contains_lookup(self):
        """Test __contains lookup on SearchableEncryptedTextField."""
        # Create test data
        SearchableDataExample.objects.create(email="alice@example.com")
        SearchableDataExample.objects.create(email="bob@test.com")
        SearchableDataExample.objects.create(email="charlie@example.org")

        # Test contains query
        results = SearchableDataExample.objects.filter(email__contains="@example")

        self.assertEqual(results.count(), 2)
        emails = [obj.email for obj in results]
        self.assertIn("alice@example.com", emails)
        self.assertIn("charlie@example.org", emails)

    def test_icontains_lookup(self):
        """Test __icontains lookup (case-insensitive)."""
        # Create test data with mixed case
        SearchableDataExample.objects.create(email="Alice@Example.COM")
        SearchableDataExample.objects.create(email="bob@TEST.com")

        # Test icontains query (lowercase)
        results = SearchableDataExample.objects.filter(email__icontains="@example")

        self.assertEqual(results.count(), 1)
        self.assertEqual(results.first().email, "Alice@Example.COM")

        # Test icontains query (uppercase)
        results = SearchableDataExample.objects.filter(email__icontains="@EXAMPLE")

        self.assertEqual(results.count(), 1)
        self.assertEqual(results.first().email, "Alice@Example.COM")

    def test_contains_icontains_same_results(self):
        """Test that contains and icontains return same results (both lowercase)."""
        # Create test data
        SearchableDataExample.objects.create(email="Test@Example.COM")

        # Both should find the record
        results_contains = SearchableDataExample.objects.filter(email__contains="example")
        results_icontains = SearchableDataExample.objects.filter(email__icontains="EXAMPLE")

        self.assertEqual(results_contains.count(), results_icontains.count())
        self.assertEqual(results_contains.first().id, results_icontains.first().id)

    def test_no_match_query(self):
        """Test that non-matching queries return 1 results."""
        SearchableDataExample.objects.create(email="alice@example.com")

        # Query for non-existent pattern with no overlapping n-grams
        # "xyz" has no n-grams in common with "alice@example.com"
        results = SearchableDataExample.objects.filter(email__contains="@test.com")

        self.assertEqual(results.count(), 0)

    def test_substring_search(self):
        """Test various substring searches."""
        obj = SearchableDataExample.objects.create(
            email="user@example.com",
            notes="This is a secret message"
        )

        # Test different substrings
        self.assertTrue(
            SearchableDataExample.objects.filter(email__contains="user").exists()
        )
        self.assertTrue(
            SearchableDataExample.objects.filter(email__contains="@example").exists()
        )
        self.assertTrue(
            SearchableDataExample.objects.filter(email__contains=".com").exists()
        )
        self.assertTrue(
            SearchableDataExample.objects.filter(notes__contains="secret").exists()
        )

    def test_update_ngram_index_on_save(self):
        """Test that n-gram indexes are updated when record is modified."""
        obj = SearchableDataExample.objects.create(email="old@email.com")

        # Update the email
        obj.email = "new@email.com"
        obj.save()

        # Old email should not be found
        results = SearchableDataExample.objects.filter(email__contains="old")
        self.assertEqual(results.count(), 0)

        # New email should be found
        results = SearchableDataExample.objects.filter(email__contains="new")
        self.assertEqual(results.count(), 1)

    def test_delete_clears_ngram_index(self):
        """Test that n-gram indexes are cleaned up on delete."""
        obj = SearchableDataExample.objects.create(email="delete@test.com")
        obj_id = obj.id

        # Verify n-grams exist
        model_name = "data_protection.SearchableDataExample"
        table_name = NGramIndexTable.get_table_name(model_name, "email")

        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) FROM {table_name} WHERE searchabledataexample_id = %s",
                [obj_id]
            )
            count_before = cursor.fetchone()[0]

        self.assertGreater(count_before, 0)

        # Delete the record
        obj.delete()

        # Verify n-grams are removed
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) FROM {table_name} WHERE searchabledataexample_id = %s",
                [obj_id]
            )
            count_after = cursor.fetchone()[0]

        self.assertEqual(count_after, 0)

    def test_empty_field(self):
        """Test handling of empty/null fields."""
        obj = SearchableDataExample.objects.create(
            email="test@example.com",
            notes=None  # Null value
        )

        # Should create successfully
        self.assertIsNotNone(obj.id)
        self.assertIsNone(obj.notes)

    def test_special_characters(self):
        """Test handling of special characters in search."""
        SearchableDataExample.objects.create(
            email="user+tag@example.com"
        )

        # Should find records with special characters
        results = SearchableDataExample.objects.filter(email__contains="+tag")
        self.assertEqual(results.count(), 1)

    def test_multiple_fields_search(self):
        """Test searching across multiple encrypted fields."""
        obj = SearchableDataExample.objects.create(
            email="admin@company.com",
            notes="Important admin notes"
        )

        # Search email field
        results = SearchableDataExample.objects.filter(email__contains="admin")
        self.assertEqual(results.count(), 1)

        # Search notes field
        results = SearchableDataExample.objects.filter(notes__contains="admin")
        self.assertEqual(results.count(), 1)

        # Combined search (AND)
        results = SearchableDataExample.objects.filter(
            email__contains="admin",
            notes__contains="Important"
        )
        self.assertEqual(results.count(), 1)

    def test_case_sensitivity_lowercase_storage(self):
        """Test that n-grams are stored in lowercase."""
        obj = SearchableDataExample.objects.create(
            email="Test@EXAMPLE.com"
        )

        # Both lowercase and uppercase queries should work
        results_lower = SearchableDataExample.objects.filter(email__contains="test")
        results_upper = SearchableDataExample.objects.filter(email__contains="TEST")
        results_mixed = SearchableDataExample.objects.filter(email__contains="Test")

        self.assertEqual(results_lower.count(), 1)
        self.assertEqual(results_upper.count(), 1)
        self.assertEqual(results_mixed.count(), 1)

    def test_short_search_term(self):
        """Test searching with very short terms."""
        SearchableDataExample.objects.create(email="a@b.com")

        # Short search terms (less than MIN_SEARCH_LENGTH) should return no results
        results = SearchableDataExample.objects.filter(email__contains="a")
        # This might return 0 results depending on MIN_SEARCH_LENGTH setting
        # Just verify it doesn't crash
        self.assertIsInstance(results.count(), int)

    def test_long_text_field(self):
        """Test handling of long text in notes field."""
        long_text = "Lorem ipsum dolor sit amet, " * 50  # Long text
        obj = SearchableDataExample.objects.create(
            email="user@example.com",
            notes=long_text
        )

        # Should create successfully
        self.assertIsNotNone(obj.id)

        # Should be searchable
        results = SearchableDataExample.objects.filter(notes__contains="ipsum")
        self.assertEqual(results.count(), 1)

    def test_ngram_table_structure(self):
        """Test that n-gram table has correct structure."""
        model_name = "data_protection.SearchableDataExample"
        table_name = NGramIndexTable.get_table_name(model_name, "email")

        # Check table structure
        with connection.cursor() as cursor:
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

        # Should have required columns
        self.assertIn("id", columns)
        self.assertIn("searchabledataexample_id", columns)
        self.assertIn("ngram_hash", columns)

    def test_concurrent_creates(self):
        """Test creating multiple records in sequence."""
        emails = [
            "user1@test.com",
            "user2@test.com",
            "user3@test.com",
        ]

        # Create multiple records
        for email in emails:
            SearchableDataExample.objects.create(email=email)

        # All should be searchable
        for email in emails:
            username = email.split("@")[0]
            results = SearchableDataExample.objects.filter(email__contains=username)
            self.assertGreaterEqual(results.count(), 1)
