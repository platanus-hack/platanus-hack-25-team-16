"""
File validation module for encrypted file fields.
Provides comprehensive file validation including MIME type checking.
"""

import os
import magic
from typing import List, Optional, Set
from django.core.exceptions import ValidationError
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class FileValidator:
    """
    Comprehensive file validation for security.

    Implements multi-layer validation:
    1. Dangerous extension blocking (configurable)
    2. File size validation
    3. Extension whitelist
    4. MIME type validation (magic numbers)
    5. MIME-extension consistency check

    ISO 27001 Controls:
    - A.12.2.1: Controls against malware
    - A.14.2.5: Secure system engineering principles
    """

    # Default dangerous extensions (can be overridden in settings)
    DEFAULT_DANGEROUS_EXTENSIONS = {
        # Executables
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".app",
        # Scripts
        ".bat",
        ".cmd",
        ".sh",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        # System files
        ".com",
        ".scr",
        ".msi",
        ".jar",
        ".deb",
        ".rpm",
        ".dmg",
        # Code files that could be executed
        ".py",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".cgi",
        # Office macros
        ".xlsm",
        ".docm",
        ".pptm",
        # Other potentially dangerous
        ".lnk",
        ".inf",
        ".reg",
        ".gadget",
    }

    # Safe MIME types (default whitelist)
    SAFE_MIMES = {
        # Documents
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",  # .docx
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",  # .xlsx
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",  # .pptx
        "application/msword",  # .doc
        "application/vnd.ms-excel",  # .xls
        "application/vnd.ms-powerpoint",  # .ppt
        # Images
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        # Text
        "text/plain",
        "text/csv",
        "text/html",
        "text/xml",
        "application/json",
        "application/xml",
        # Archives (use with caution)
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
    }

    # MIME to extension mapping for consistency validation
    MIME_EXTENSION_MAP = {
        "application/pdf": {".pdf"},
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
            ".docx"
        },
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
            ".pptx"
        },
        "application/msword": {".doc"},
        "application/vnd.ms-excel": {".xls"},
        "application/vnd.ms-powerpoint": {".ppt"},
        "image/jpeg": {".jpg", ".jpeg"},
        "image/png": {".png"},
        "image/gif": {".gif"},
        "image/webp": {".webp"},
        "image/svg+xml": {".svg"},
        "text/plain": {".txt"},
        "text/csv": {".csv"},
        "text/html": {".html", ".htm"},
        "text/xml": {".xml"},
        "application/json": {".json"},
        "application/xml": {".xml"},
        "application/zip": {".zip"},
        "application/x-rar-compressed": {".rar"},
        "application/x-7z-compressed": {".7z"},
    }

    def __init__(self):
        """Initialize validator with settings."""
        self.django_sec = getattr(settings, "DJANGO_SEC", {})
        self.encrypted_files_config = self.django_sec.get("ENCRYPTED_FILES", {})

    def get_dangerous_extensions(self) -> Set[str]:
        """
        Get the set of dangerous extensions from settings or defaults.

        Returns configured dangerous extensions from settings,
        or default set if not configured.
        """
        configured = self.encrypted_files_config.get("DANGEROUS_EXTENSIONS")

        if configured is None:
            return self.DEFAULT_DANGEROUS_EXTENSIONS

        if isinstance(configured, (list, set, tuple)):
            # Ensure all extensions start with '.'
            return {ext if ext.startswith(".") else f".{ext}" for ext in configured}

        logger.warning(
            "DANGEROUS_EXTENSIONS must be a list, set, or tuple. Using defaults."
        )
        return self.DEFAULT_DANGEROUS_EXTENSIONS

    def validate(
        self,
        file,
        max_size: Optional[int] = None,
        allowed_extensions: Optional[List[str]] = None,
        allowed_mimetypes: Optional[List[str]] = None,
        validate_mime: bool = True,
        dangerous_extensions: Optional[Set[str]] = None,
    ) -> bool:
        """
        Perform comprehensive file validation.

        Args:
            file: Django UploadedFile object
            max_size: Maximum file size in bytes
            allowed_extensions: Whitelist of allowed extensions
            allowed_mimetypes: Whitelist of allowed MIME types
            validate_mime: Whether to validate actual MIME type
            dangerous_extensions: Custom set of dangerous extensions

        Returns:
            True if validation passes

        Raises:
            ValidationError: If any validation fails
        """
        # Get filename and extension
        filename = file.name
        extension = os.path.splitext(filename)[1].lower()

        # 1. Check dangerous extensions
        if dangerous_extensions is None:
            dangerous_extensions = self.get_dangerous_extensions()

        if extension in dangerous_extensions:
            logger.warning(f"Blocked dangerous file extension: {extension}")
            raise ValidationError(
                f"File type '{extension}' is not allowed for security reasons. "
                f"Dangerous file types include executables and scripts."
            )

        # 2. Check file size
        if max_size and file.size > max_size:
            raise ValidationError(
                f"File size ({self._human_readable_size(file.size)}) exceeds maximum allowed size "
                f"({self._human_readable_size(max_size)})"
            )

        # 3. Check allowed extensions (if specified)
        if allowed_extensions:
            # Normalize extensions to include dot
            normalized_extensions = {
                ext if ext.startswith(".") else f".{ext}" for ext in allowed_extensions
            }
            if extension not in normalized_extensions:
                raise ValidationError(
                    f"File extension '{extension}' is not in the allowed list: "
                    f"{', '.join(sorted(normalized_extensions))}"
                )

        # 4. Validate MIME type if enabled
        if validate_mime:
            file.seek(0)
            try:
                # Use python-magic to detect actual MIME type
                actual_mime = magic.from_buffer(file.read(2048), mime=True)
                file.seek(0)
            except Exception as e:
                logger.error(f"Error detecting MIME type: {e}")
                raise ValidationError("Could not determine file type")

            logger.debug(f"File {filename}: detected MIME type {actual_mime}")

            # Check against allowed MIME types
            if allowed_mimetypes:
                if actual_mime not in allowed_mimetypes:
                    raise ValidationError(
                        f"File type '{actual_mime}' is not allowed. "
                        f"Allowed types: {', '.join(sorted(allowed_mimetypes))}"
                    )
            else:
                # Use default safe MIME types
                if actual_mime not in self.SAFE_MIMES:
                    raise ValidationError(
                        f"File type '{actual_mime}' is not in the list of safe file types"
                    )

            # 5. Validate MIME-extension consistency
            if not self._validate_mime_extension_match(actual_mime, extension):
                raise ValidationError(
                    f"File extension '{extension}' doesn't match detected file type '{actual_mime}'. "
                    f"The file may be disguised or corrupted."
                )

        # All validations passed
        logger.info(f"File {filename} passed all validations")
        return True

    def _validate_mime_extension_match(self, mime_type: str, extension: str) -> bool:
        """
        Validate that file extension matches its MIME type.

        Args:
            mime_type: Detected MIME type
            extension: File extension

        Returns:
            True if extension matches MIME type
        """
        # Get valid extensions for this MIME type
        valid_extensions = self.MIME_EXTENSION_MAP.get(mime_type, set())

        # If we don't have a mapping, be lenient (log warning)
        if not valid_extensions:
            logger.warning(
                f"No extension mapping found for MIME type '{mime_type}'. "
                f"Consider adding it to MIME_EXTENSION_MAP."
            )
            return True

        return extension in valid_extensions

    @staticmethod
    def _human_readable_size(size: int) -> str:
        """Convert size in bytes to human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def validate_content_safety(self, file) -> bool:
        """
        Additional content validation for specific file types.
        Can be extended to check for embedded scripts, macros, etc.

        Args:
            file: File to validate

        Returns:
            True if content is safe

        Raises:
            ValidationError: If dangerous content is detected
        """
        # This can be extended in the future for:
        # - PDF JavaScript detection
        # - Office macro detection
        # - ZIP bomb detection
        # - SVG script detection

        file.seek(0)
        content_start = file.read(1024)
        file.seek(0)

        # Check for common script indicators in files that shouldn't have them
        suspicious_patterns = [
            b"<script",
            b"javascript:",
            b"eval(",
            b"document.write",
            b"window.location",
        ]

        # Get file extension
        extension = os.path.splitext(file.name)[1].lower()

        # Check for suspicious content in text-based files
        if extension in [".txt", ".csv", ".log"]:
            for pattern in suspicious_patterns:
                if pattern in content_start.lower():
                    raise ValidationError(
                        "File contains suspicious content that looks like executable code"
                    )

        return True


class MimeTypeDetector:
    """
    Helper class for MIME type detection using python-magic.
    """

    @staticmethod
    def get_mime_type(file) -> str:
        """
        Detect MIME type of a file using magic numbers.

        Args:
            file: File-like object

        Returns:
            MIME type string
        """
        file.seek(0)
        mime_type = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)
        return mime_type

    @staticmethod
    def get_file_type_description(file) -> str:
        """
        Get human-readable file type description.

        Args:
            file: File-like object

        Returns:
            Description string
        """
        file.seek(0)
        description = magic.from_buffer(file.read(2048))
        file.seek(0)
        return description
