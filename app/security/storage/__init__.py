"""
Security storage module for encrypted file handling.

Use lazy imports to avoid circular dependency issues during Django app loading.
"""

__all__ = [
    "EncryptedFileField",
    "FileValidator",
    "SignedURLManager",
]


def __getattr__(name):
    """Lazy import to avoid circular dependencies."""
    if name == "EncryptedFileField":
        from .encrypted_file_field import EncryptedFileField

        return EncryptedFileField
    elif name == "FileValidator":
        from .validators import FileValidator

        return FileValidator
    elif name == "SignedURLManager":
        from .signed_urls import SignedURLManager

        return SignedURLManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
