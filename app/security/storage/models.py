"""
Database models for encrypted file storage and auditing.
"""

from django.db import models
from django.conf import settings
from django.utils import timezone


class FileMetadata(models.Model):
    """
    Stores metadata about encrypted files.

    ISO 27001 Controls:
    - A.12.4.1: Event logging
    - A.10.1.2: Key management
    """

    file_path = models.CharField(
        max_length=500, unique=True, help_text="Path to the encrypted file"
    )
    original_name = models.CharField(
        max_length=255, help_text="Original filename before encryption"
    )
    file_hash = models.CharField(
        max_length=64, help_text="SHA-256 hash of the original file"
    )
    size = models.BigIntegerField(help_text="Size of the encrypted file in bytes")
    encryption_backend = models.CharField(
        max_length=50, default="fernet", help_text="Encryption backend used"
    )
    uploaded_at = models.DateTimeField(
        default=timezone.now, help_text="When the file was uploaded"
    )
    model_name = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text="Django model this file belongs to",
    )
    model_pk = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text="Primary key of the model instance",
    )
    is_active = models.BooleanField(
        default=True, help_text="Whether this file is still active"
    )
    deleted_at = models.DateTimeField(
        null=True, blank=True, help_text="When the file was marked as deleted"
    )

    class Meta:
        verbose_name = "File Metadata"
        verbose_name_plural = "File Metadata"
        indexes = [
            models.Index(fields=["file_path"]),
            models.Index(fields=["file_hash"]),
            models.Index(fields=["uploaded_at"]),
            models.Index(fields=["model_name", "model_pk"]),
        ]
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"{self.original_name} ({self.file_path})"


class FileAccessLog(models.Model):
    """
    Audit log for all file operations.

    Tracks uploads, downloads, deletions, and access attempts.

    ISO 27001 Controls:
    - A.12.4.1: Event logging
    - A.12.4.3: Administrator and operator logs
    - A.16.1.7: Collection of evidence
    """

    ACTION_CHOICES = [
        ("upload", "File Upload"),
        ("download", "File Download"),
        ("download_via_signed_url", "Download via Signed URL"),
        ("decrypt", "File Decryption"),
        ("delete", "File Deletion"),
        ("generate_url", "Generate Signed URL"),
        ("access_denied", "Access Denied"),
        ("validation_failed", "Validation Failed"),
    ]

    STATUS_CHOICES = [
        ("success", "Success"),
        ("failed", "Failed"),
        ("denied", "Denied"),
    ]

    timestamp = models.DateTimeField(
        auto_now_add=True, help_text="When the action occurred"
    )
    file_path = models.CharField(max_length=500, help_text="Path to the file")
    action = models.CharField(
        max_length=30, choices=ACTION_CHOICES, help_text="Type of action performed"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="file_access_logs",
        help_text="User who performed the action",
    )
    ip_address = models.GenericIPAddressField(help_text="IP address of the request")
    user_agent = models.TextField(null=True, blank=True, help_text="User agent string")
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default="success",
        help_text="Status of the operation",
    )
    error_message = models.TextField(
        null=True, blank=True, help_text="Error message if operation failed"
    )
    metadata = models.JSONField(
        default=dict, blank=True, help_text="Additional metadata about the operation"
    )

    class Meta:
        verbose_name = "File Access Log"
        verbose_name_plural = "File Access Logs"
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["file_path"]),
            models.Index(fields=["user"]),
            models.Index(fields=["action"]),
            models.Index(fields=["ip_address"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.action} - {self.file_path} - {self.timestamp}"


class FileValidationLog(models.Model):
    """
    Log of file validation attempts and results.

    ISO 27001 Controls:
    - A.12.2.1: Controls against malware
    - A.14.2.5: Secure system engineering principles
    """

    VALIDATION_TYPE_CHOICES = [
        ("size", "File Size"),
        ("extension", "File Extension"),
        ("mime", "MIME Type"),
        ("dangerous", "Dangerous File Check"),
        ("content", "Content Validation"),
    ]

    timestamp = models.DateTimeField(
        auto_now_add=True, help_text="When the validation occurred"
    )
    filename = models.CharField(
        max_length=255, help_text="Name of the file being validated"
    )
    validation_type = models.CharField(
        max_length=20,
        choices=VALIDATION_TYPE_CHOICES,
        help_text="Type of validation performed",
    )
    passed = models.BooleanField(help_text="Whether the validation passed")
    detected_value = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="What was detected (e.g., MIME type, file size)",
    )
    expected_value = models.CharField(
        max_length=255, null=True, blank=True, help_text="What was expected"
    )
    error_message = models.TextField(
        null=True, blank=True, help_text="Detailed error message"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who uploaded the file",
    )
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, help_text="IP address of the upload request"
    )

    class Meta:
        verbose_name = "File Validation Log"
        verbose_name_plural = "File Validation Logs"
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["validation_type"]),
            models.Index(fields=["passed"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self):
        status = "✓" if self.passed else "✗"
        return f"{status} {self.validation_type} - {self.filename} - {self.timestamp}"


class SignedURLLog(models.Model):
    """
    Track generation and usage of signed URLs.

    ISO 27001 Controls:
    - A.9.4.1: Information access restriction
    - A.13.2.1: Information transfer policies
    """

    created_at = models.DateTimeField(
        auto_now_add=True, help_text="When the signed URL was created"
    )
    file_path = models.CharField(max_length=500, help_text="Path to the file")
    expires_at = models.DateTimeField(help_text="When the URL expires")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_signed_urls",
        help_text="User who created the signed URL",
    )
    created_for_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address the URL was created for (if IP-bound)",
    )
    permissions = models.JSONField(
        default=list, help_text="Permissions granted by this URL"
    )
    used_count = models.IntegerField(
        default=0, help_text="Number of times this URL was used"
    )
    last_used_at = models.DateTimeField(
        null=True, blank=True, help_text="When the URL was last used"
    )
    last_used_by_ip = models.GenericIPAddressField(
        null=True, blank=True, help_text="IP address that last used this URL"
    )
    revoked = models.BooleanField(
        default=False, help_text="Whether this URL has been revoked"
    )
    revoked_at = models.DateTimeField(
        null=True, blank=True, help_text="When the URL was revoked"
    )
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_signed_urls",
        help_text="User who revoked the URL",
    )

    class Meta:
        verbose_name = "Signed URL Log"
        verbose_name_plural = "Signed URL Logs"
        indexes = [
            models.Index(fields=["created_at"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["file_path"]),
            models.Index(fields=["created_by"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"URL for {self.file_path} - Expires: {self.expires_at}"

    @property
    def is_expired(self):
        """Check if the URL has expired."""
        return timezone.now() > self.expires_at

    @property
    def is_active(self):
        """Check if the URL is still active (not expired or revoked)."""
        return not self.revoked and not self.is_expired
