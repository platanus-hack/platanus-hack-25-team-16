"""
Encrypted file field implementation for Django models.
Provides encryption at rest, file validation, and signed URLs.
"""

import os
import hashlib
from typing import Optional, List, Any
from django.db import models
from django.core.files.base import ContentFile
from django.conf import settings
from django.utils import timezone
from cryptography.fernet import Fernet
import logging

from .validators import FileValidator
from .signed_urls import SignedURLManager
from .models import FileAccessLog, FileMetadata

logger = logging.getLogger(__name__)


class EncryptedFileField(models.FileField):
    """
    A Django FileField that automatically encrypts files at rest.

    Features:
    - AES-256 encryption using Fernet
    - File type validation (extension and MIME)
    - Configurable size limits
    - Signed URLs with expiration
    - Audit logging

    ISO 27001 Controls:
    - A.10.1.1: Policy on the use of cryptographic controls
    - A.10.1.2: Key management
    - A.12.4.1: Event logging
    - A.13.2.1: Information transfer policies
    """

    description = "Encrypted file storage with validation and signed URLs"

    def __init__(
        self,
        upload_to: str = "encrypted/",
        max_upload_size: Optional[int] = None,
        allowed_extensions: Optional[List[str]] = None,
        allowed_mimetypes: Optional[List[str]] = None,
        validate_mime: bool = True,
        signed_url_expiry: int = 3600,
        encryption_backend: str = "fernet",
        audit_access: bool = True,
        **kwargs,
    ):
        """
        Initialize an encrypted file field.

        Args:
            upload_to: Directory where encrypted files will be stored
            max_upload_size: Maximum file size in bytes (None = use settings default)
            allowed_extensions: List of allowed file extensions (e.g., ['.pdf', '.docx'])
            allowed_mimetypes: List of allowed MIME types
            validate_mime: Whether to validate actual file content vs extension
            signed_url_expiry: Default expiry time for signed URLs in seconds
            encryption_backend: Encryption backend to use ('fernet', 'kms_aws', etc.)
            audit_access: Whether to log file access events
        """
        self.max_upload_size = max_upload_size or self._get_default_max_size()
        self.allowed_extensions = allowed_extensions or []
        self.allowed_mimetypes = allowed_mimetypes
        self.validate_mime = validate_mime
        self.signed_url_expiry = signed_url_expiry
        self.encryption_backend = encryption_backend
        self.audit_access = audit_access

        # Initialize encryption cipher
        self.cipher = self._initialize_cipher()

        # Initialize URL manager
        self.url_manager = SignedURLManager()

        # Ensure upload_to ends with /
        if upload_to and not upload_to.endswith("/"):
            upload_to += "/"

        super().__init__(upload_to=upload_to, **kwargs)

    def _get_default_max_size(self) -> int:
        """Get default max file size from settings."""
        django_sec = getattr(settings, "DJANGO_SEC", {})
        encrypted_files = django_sec.get("ENCRYPTED_FILES", {})
        return encrypted_files.get("MAX_SIZE", 10 * 1024 * 1024)  # 10MB default

    def _initialize_cipher(self) -> Fernet:
        """Initialize the encryption cipher based on backend."""
        if self.encryption_backend == "fernet":
            django_sec = getattr(settings, "DJANGO_SEC", {})
            encryption_key = django_sec.get("FILE_ENCRYPTION_KEY")

            if not encryption_key:
                # Try to get from environment
                encryption_key = os.environ.get("FILE_ENCRYPTION_KEY")

            if not encryption_key:
                # Generate a key in development mode only
                if settings.DEBUG:
                    logger.warning(
                        "FILE_ENCRYPTION_KEY not set. Generating a temporary key for development. "
                        "DO NOT use this in production!"
                    )
                    encryption_key = Fernet.generate_key()
                else:
                    raise ValueError(
                        "FILE_ENCRYPTION_KEY must be set in DJANGO_SEC settings or environment for production"
                    )

            # Ensure the key is bytes
            if isinstance(encryption_key, str):
                encryption_key = encryption_key.encode()

            try:
                return Fernet(encryption_key)
            except Exception as e:
                raise ValueError(f"Invalid encryption key: {e}")
        else:
            raise NotImplementedError(
                f"Encryption backend '{self.encryption_backend}' not implemented yet"
            )

    def pre_save(self, model_instance: models.Model, add: bool) -> Any:
        """
        Called before saving the model instance.
        Validates and encrypts the file.
        """
        file = getattr(model_instance, self.attname)

        if file and not file._committed:
            try:
                # Validate the file
                self._validate_file(file)

                # Generate file hash for integrity
                file_hash = self._calculate_file_hash(file)

                # Encrypt the file content
                encrypted_content = self._encrypt_file(file)

                # Modify filename to indicate encryption
                original_name = file.name
                encrypted_name = f"{file_hash[:16]}_{original_name}.enc"

                # Save encrypted file
                file.save(encrypted_name, ContentFile(encrypted_content), save=False)

                # Store metadata
                self._store_file_metadata(
                    file_path=file.name,
                    original_name=original_name,
                    file_hash=file_hash,
                    size=len(encrypted_content),
                    model_instance=model_instance,
                )

                # Audit log
                if self.audit_access:
                    self._log_file_operation("upload", file.name, model_instance)

            except Exception as e:
                logger.error(f"Error processing encrypted file: {e}")
                raise

        return super().pre_save(model_instance, add)

    def _validate_file(self, file) -> None:
        """
        Validate the file using FileValidator.

        Raises:
            ValidationError: If file validation fails
        """
        # Reset file pointer
        file.seek(0)

        # Get validation settings
        django_sec = getattr(settings, "DJANGO_SEC", {})
        encrypted_files = django_sec.get("ENCRYPTED_FILES", {})

        # Use FileValidator
        validator = FileValidator()
        validator.validate(
            file=file,
            max_size=self.max_upload_size,
            allowed_extensions=self.allowed_extensions,
            allowed_mimetypes=self.allowed_mimetypes,
            validate_mime=self.validate_mime,
            dangerous_extensions=encrypted_files.get("DANGEROUS_EXTENSIONS"),
        )

    def _calculate_file_hash(self, file) -> str:
        """Calculate SHA-256 hash of file content."""
        file.seek(0)
        sha256_hash = hashlib.sha256()

        # Read file in chunks to handle large files
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

        file.seek(0)
        return sha256_hash.hexdigest()

    def _encrypt_file(self, file) -> bytes:
        """
        Encrypt file content using configured cipher.

        Returns:
            Encrypted file content as bytes
        """
        file.seek(0)
        content = file.read()

        # Ensure content is bytes
        if isinstance(content, str):
            content = content.encode()

        encrypted = self.cipher.encrypt(content)

        logger.debug(f"Encrypted file of size {len(content)} -> {len(encrypted)} bytes")
        return encrypted

    def decrypt_file(self, file_path: str) -> bytes:
        """
        Decrypt a file for reading.

        Args:
            file_path: Path to the encrypted file

        Returns:
            Decrypted file content
        """
        try:
            # Read encrypted content
            with self.storage.open(file_path, "rb") as f:
                encrypted_content = f.read()

            # Decrypt
            decrypted = self.cipher.decrypt(encrypted_content)

            # Audit log
            if self.audit_access:
                self._log_file_operation("decrypt", file_path)

            return decrypted

        except Exception as e:
            logger.error(f"Error decrypting file {file_path}: {e}")
            raise

    def generate_signed_url(
        self,
        file_instance,
        expires_in: Optional[int] = None,
        permissions: List[str] = None,
        bind_to_ip: bool = False,
    ) -> str:
        """
        Generate a signed URL for temporary file access.

        Args:
            file_instance: The file field instance
            expires_in: Expiry time in seconds (uses default if not specified)
            permissions: List of permissions for the URL (default: ['read'])
            bind_to_ip: Whether to bind the URL to the requester's IP

        Returns:
            Signed URL string
        """
        if expires_in is None:
            expires_in = self.signed_url_expiry

        if permissions is None:
            permissions = ["read"]

        # Get file path
        file_path = (
            file_instance.name if hasattr(file_instance, "name") else str(file_instance)
        )

        # Generate signed URL
        signed_url = self.url_manager.generate_url(
            file_path=file_path,
            expires_in=expires_in,
            permissions=permissions,
            bind_to_ip=bind_to_ip,
        )

        # Audit log
        if self.audit_access:
            self._log_file_operation("generate_url", file_path)

        return signed_url

    def _store_file_metadata(
        self,
        file_path: str,
        original_name: str,
        file_hash: str,
        size: int,
        model_instance: models.Model,
    ) -> None:
        """Store file metadata for tracking and auditing."""
        try:
            FileMetadata.objects.update_or_create(
                file_path=file_path,
                defaults={
                    "original_name": original_name,
                    "file_hash": file_hash,
                    "size": size,
                    "encryption_backend": self.encryption_backend,
                    "uploaded_at": timezone.now(),
                    "model_name": model_instance.__class__.__name__,
                    "model_pk": str(model_instance.pk) if model_instance.pk else None,
                },
            )
        except Exception as e:
            logger.warning(f"Could not store file metadata: {e}")

    def _log_file_operation(
        self, action: str, file_path: str, model_instance: models.Model = None
    ) -> None:
        """Log file operations for audit trail."""
        try:
            # Try to get current user (if in request context)
            user = None
            try:
                from app.security.utils.helpers import get_current_user

                user = get_current_user()
            except:  # noqa: E722
                pass

            # Try to get IP address
            ip_address = None
            try:
                from app.security.utils.helpers import get_client_ip

                ip_address = get_client_ip()
            except:  # noqa: E722
                pass

            FileAccessLog.objects.create(
                file_path=file_path,
                action=action,
                user=user,
                ip_address=ip_address or "0.0.0.0",
                status="success",
                metadata={
                    "model": model_instance.__class__.__name__
                    if model_instance
                    else None,
                    "model_pk": str(model_instance.pk)
                    if model_instance and model_instance.pk
                    else None,
                },
            )
        except Exception as e:
            logger.warning(f"Could not log file operation: {e}")

    def contribute_to_class(self, cls, name, **kwargs):
        """Add helper methods to the model class."""
        super().contribute_to_class(cls, name, **kwargs)

        # Add helper method to get signed URL
        def get_signed_url(model_instance, expires_in=None):
            field = getattr(model_instance, name)
            if field:
                return self.generate_signed_url(field, expires_in=expires_in)
            return None

        # Add helper method to get decrypted content
        def get_decrypted_content(model_instance):
            field = getattr(model_instance, name)
            if field:
                return self.decrypt_file(field.name)
            return None

        setattr(cls, f"get_{name}_signed_url", get_signed_url)
        setattr(cls, f"get_{name}_decrypted", get_decrypted_content)
