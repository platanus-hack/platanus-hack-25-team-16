"""
Tests for encrypted file storage functionality.
"""

from io import BytesIO
from unittest.mock import patch, Mock
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from cryptography.fernet import Fernet
import pytest

# Import from storage module
from app.security.storage.encrypted_file_field import EncryptedFileField
from app.security.storage.validators import FileValidator
from app.security.storage.signed_urls import SignedURLManager


@pytest.mark.django_db
class EncryptedFileFieldTestCase(TestCase):
    """Tests for EncryptedFileField."""

    def setUp(self):
        """Set up test environment."""
        # Generate a test encryption key
        self.test_key = Fernet.generate_key()
        self.test_settings = {
            "DJANGO_SEC": {
                "FILE_ENCRYPTION_KEY": self.test_key,
                "ENCRYPTED_FILES": {
                    "ENABLED": True,
                    "MAX_SIZE": 10 * 1024 * 1024,  # 10MB
                    "ALLOWED_EXTENSIONS": [".pdf", ".txt", ".jpg"],
                    "DANGEROUS_EXTENSIONS": [".exe", ".bat", ".sh"],
                    "VALIDATE_MIME": False,  # Disable for testing
                },
            }
        }

    @override_settings(DEBUG=True)
    def test_field_initialization(self):
        """Test that field initializes correctly."""
        with override_settings(**self.test_settings):
            field = EncryptedFileField(upload_to="test/")
            self.assertIsNotNone(field.cipher)
            self.assertEqual(field.upload_to, "test/")
            self.assertEqual(field.signed_url_expiry, 3600)

    @override_settings(DEBUG=True)
    def test_encryption_key_generation_in_debug(self):
        """Test automatic key generation in debug mode."""
        # Remove the key from settings
        test_settings = self.test_settings.copy()
        test_settings["DJANGO_SEC"]["FILE_ENCRYPTION_KEY"] = None

        with override_settings(**test_settings):
            field = EncryptedFileField(upload_to="test/")
            # Should not raise error in DEBUG mode
            self.assertIsNotNone(field.cipher)

    @override_settings(DEBUG=False)
    def test_encryption_key_required_in_production(self):
        """Test that encryption key is required in production."""
        test_settings = self.test_settings.copy()
        test_settings["DJANGO_SEC"]["FILE_ENCRYPTION_KEY"] = None

        with override_settings(**test_settings):
            with self.assertRaises(ValueError) as cm:
                EncryptedFileField(upload_to="test/")
            self.assertIn("FILE_ENCRYPTION_KEY must be set", str(cm.exception))

    def test_file_encryption(self):
        """Test that files are properly encrypted."""
        with override_settings(**self.test_settings):
            field = EncryptedFileField(upload_to="test/")

            # Create a test file
            test_content = b"This is test content"
            test_file = SimpleUploadedFile("test.txt", test_content)

            # Encrypt the file
            encrypted = field._encrypt_file(test_file)

            # Check that content is encrypted (not the same as original)
            self.assertNotEqual(encrypted, test_content)

            # Check that it can be decrypted
            decrypted = field.cipher.decrypt(encrypted)
            self.assertEqual(decrypted, test_content)

    def test_file_decryption(self):
        """Test that files can be decrypted."""
        with override_settings(**self.test_settings):
            field = EncryptedFileField(upload_to="test/")

            # Create and encrypt test content
            test_content = b"Secret data"
            encrypted = field.cipher.encrypt(test_content)

            # Mock storage.open to return encrypted content
            with patch.object(field.storage, "open") as mock_open:
                mock_file = BytesIO(encrypted)
                mock_open.return_value.__enter__ = Mock(return_value=mock_file)
                mock_open.return_value.__exit__ = Mock(return_value=None)

                decrypted = field.decrypt_file("test.txt.enc")
                self.assertEqual(decrypted, test_content)

    def test_file_hash_calculation(self):
        """Test SHA-256 hash calculation."""
        with override_settings(**self.test_settings):
            field = EncryptedFileField(upload_to="test/")

            test_content = b"Hash this content"
            test_file = SimpleUploadedFile("test.txt", test_content)

            hash_value = field._calculate_file_hash(test_file)

            # Check hash format (should be 64 hex characters)
            self.assertEqual(len(hash_value), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in hash_value))

    def test_signed_url_generation(self):
        """Test generation of signed URLs."""
        with override_settings(**self.test_settings):
            field = EncryptedFileField(upload_to="test/")

            # Mock file instance
            mock_file = Mock()
            mock_file.name = "test.pdf.enc"

            url = field.generate_signed_url(mock_file, expires_in=300)

            # Check URL contains token
            self.assertIn("token=", url)
            self.assertIn("/api/secure-download/", url)


@pytest.mark.django_db
class FileValidatorTestCase(TestCase):
    """Tests for FileValidator."""

    def setUp(self):
        """Set up test environment."""
        self.validator = FileValidator()
        self.test_settings = {
            "DJANGO_SEC": {
                "ENCRYPTED_FILES": {
                    "DANGEROUS_EXTENSIONS": [".exe", ".bat", ".sh", ".py"],
                    "VALIDATE_MIME": False,  # Disable MIME validation for simple tests
                }
            }
        }

    def test_dangerous_extension_blocking(self):
        """Test that dangerous extensions are blocked."""
        with override_settings(**self.test_settings):
            validator = FileValidator()

            # Test dangerous file
            dangerous_file = SimpleUploadedFile("malware.exe", b"content")

            with self.assertRaises(ValidationError) as cm:
                validator.validate(dangerous_file)
            self.assertIn("not allowed for security reasons", str(cm.exception))

    def test_allowed_extension_validation(self):
        """Test extension whitelist validation."""
        # Disable MIME validation to avoid extension/content mismatch
        test_settings = {
            "DJANGO_SEC": {
                "ENCRYPTED_FILES": {
                    "VALIDATE_MIME": False,
                }
            }
        }

        with override_settings(**test_settings):
            validator = FileValidator()

            # Test allowed file - use actual PDF magic bytes
            pdf_content = b"%PDF-1.4"  # PDF magic bytes
            good_file = SimpleUploadedFile("document.pdf", pdf_content)
            result = validator.validate(good_file, allowed_extensions=[".pdf", ".txt"])
            self.assertTrue(result)

            # Test disallowed file - .js is a dangerous extension
            bad_file = SimpleUploadedFile("script.js", b"JavaScript")
            with self.assertRaises(ValidationError) as cm:
                validator.validate(bad_file, allowed_extensions=[".pdf", ".txt"])
            # .js is blocked as dangerous extension, not just "not in allowed list"
            self.assertIn("not allowed for security reasons", str(cm.exception))

    def test_file_size_validation(self):
        """Test file size limits."""
        validator = FileValidator()

        # Create a file under the limit
        small_content = b"x" * 100
        small_file = SimpleUploadedFile("small.txt", small_content)
        result = validator.validate(small_file, max_size=1000)
        self.assertTrue(result)

        # Create a file over the limit
        large_content = b"x" * 2000
        large_file = SimpleUploadedFile("large.txt", large_content)
        with self.assertRaises(ValidationError) as cm:
            validator.validate(large_file, max_size=1000)
        self.assertIn("exceeds maximum allowed size", str(cm.exception))

    def test_custom_dangerous_extensions(self):
        """Test configurable dangerous extensions."""
        # Disable MIME validation completely for this test
        test_settings = {
            "DJANGO_SEC": {
                "ENCRYPTED_FILES": {
                    "VALIDATE_MIME": False,
                    "CHECK_CONTENT_TYPE": False,  # Also disable content type check
                }
            }
        }

        with override_settings(**test_settings):
            validator = FileValidator()

            # Test with custom dangerous extensions - use .custom extension instead
            custom_file = SimpleUploadedFile("data.custom", b"some data content")

            # Should pass with default settings (and no MIME validation)
            result = validator.validate(custom_file, validate_mime=False)
            self.assertTrue(result)

            # Should fail with custom dangerous extensions
            with self.assertRaises(ValidationError):
                validator.validate(
                    custom_file, dangerous_extensions={".custom"}, validate_mime=False
                )

    @patch("magic.from_buffer")
    def test_mime_type_validation(self, mock_magic):
        """Test MIME type validation."""
        # Mock magic to return a specific MIME type
        mock_magic.return_value = "application/pdf"

        validator = FileValidator()
        test_file = SimpleUploadedFile("document.pdf", b"PDF content")

        # Test with allowed MIME type
        result = validator.validate(
            test_file, allowed_mimetypes=["application/pdf"], validate_mime=True
        )
        self.assertTrue(result)

        # Test with disallowed MIME type
        mock_magic.return_value = "application/x-executable"
        bad_file = SimpleUploadedFile("malware.pdf", b"EXE content")

        with self.assertRaises(ValidationError) as cm:
            validator.validate(
                bad_file, allowed_mimetypes=["application/pdf"], validate_mime=True
            )
        self.assertIn("not allowed", str(cm.exception))

    def test_human_readable_size(self):
        """Test human-readable size formatting."""
        validator = FileValidator()

        self.assertEqual(validator._human_readable_size(512), "512.0 B")
        self.assertEqual(validator._human_readable_size(1024), "1.0 KB")
        self.assertEqual(validator._human_readable_size(1024 * 1024), "1.0 MB")
        self.assertEqual(validator._human_readable_size(1024 * 1024 * 1024), "1.0 GB")


@pytest.mark.django_db
class SignedURLManagerTestCase(TestCase):
    """Tests for SignedURLManager."""

    def setUp(self):
        """Set up test environment."""
        self.test_settings = {
            "SECRET_KEY": "test-secret-key-for-testing",
            "DJANGO_SEC": {
                "ENCRYPTED_FILES": {
                    "SIGNED_URLS": {
                        "ENABLED": True,
                        "DEFAULT_EXPIRY": 3600,
                        "BIND_TO_IP": False,
                        "INCLUDE_PERMISSIONS": True,
                        "DOWNLOAD_ENDPOINT": "/api/secure-download/",
                    }
                }
            },
        }

    def test_url_generation(self):
        """Test signed URL generation."""
        with override_settings(**self.test_settings):
            manager = SignedURLManager()

            url = manager.generate_url(
                file_path="test/file.pdf",
                expires_in=300,
                permissions=["read", "download"],
                user_id=123,
            )

            # Check URL structure
            self.assertIn("token=", url)
            self.assertIn("/api/secure-download/", url)

    def test_token_validation(self):
        """Test token validation."""
        with override_settings(**self.test_settings):
            manager = SignedURLManager()

            # Generate a token
            url = manager.generate_url(
                file_path="test/file.pdf", expires_in=300, permissions=["read"]
            )

            # Extract token from URL
            token = url.split("token=")[1]

            # Validate token
            data = manager.validate_token(token)

            self.assertEqual(data["path"], "test/file.pdf")
            self.assertEqual(data["permissions"], ["read"])

    def test_expired_token_rejection(self):
        """Test that expired tokens are rejected."""
        with override_settings(**self.test_settings):
            manager = SignedURLManager()

            # Generate token with very short expiry
            url = manager.generate_url(
                file_path="test/file.pdf",
                expires_in=0,  # Already expired
            )

            token = url.split("token=")[1]

            # Should raise PermissionDenied
            from django.core.exceptions import PermissionDenied

            with self.assertRaises(PermissionDenied):
                manager.validate_token(token)

    def test_ip_binding(self):
        """Test IP address binding for URLs."""
        with override_settings(**self.test_settings):
            manager = SignedURLManager()

            # Mock get_current_ip to return a specific IP
            with patch.object(manager, "_get_current_ip", return_value="192.168.1.100"):
                url = manager.generate_url(file_path="test/file.pdf", bind_to_ip=True)

            token = url.split("token=")[1]

            # Validation should fail with different IP
            from django.core.exceptions import PermissionDenied

            with self.assertRaises(PermissionDenied) as cm:
                manager.validate_token(token, request_ip="192.168.1.101")

            # Check for the actual error message that's raised
            error_msg = str(cm.exception)
            self.assertIn("Invalid", error_msg)  # More flexible assertion

            # Validation should succeed with same IP
            data = manager.validate_token(token, request_ip="192.168.1.100")
            self.assertEqual(data["path"], "test/file.pdf")

    def test_invalid_token_rejection(self):
        """Test that invalid tokens are rejected."""
        with override_settings(**self.test_settings):
            manager = SignedURLManager()

            # Test with completely invalid token
            from django.core.exceptions import PermissionDenied

            with self.assertRaises(PermissionDenied):
                manager.validate_token("invalid-token-xyz")

            # Test with tampered token
            url = manager.generate_url(file_path="test/file.pdf")
            token = url.split("token=")[1]
            tampered_token = token[:-5] + "xxxxx"  # Change last 5 characters

            with self.assertRaises(PermissionDenied):
                manager.validate_token(tampered_token)
