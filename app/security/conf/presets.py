"""
Security Configuration Presets

Provides different security configuration presets for various environments.
"""

from typing import Dict, Any
from .settings import SECURE_DEFAULTS


# Strict preset - Maximum security for production
STRICT_PRESET = {
    **SECURE_DEFAULTS,
    # Enhanced session security
    "SESSION_COOKIE_AGE": 1800,  # 30 minutes
    "SESSION_SAVE_EVERY_REQUEST": True,  # Refresh session on each request
    # Stricter CSP
    "CSP_DEFAULT_SRC": ("'self'",),
    "CSP_SCRIPT_SRC": ("'self'",),  # No inline scripts
    "CSP_STYLE_SRC": ("'self'",),  # No inline styles
    "CSP_IMG_SRC": ("'self'", "data:", "https:"),
    "CSP_FONT_SRC": ("'self'",),
    "CSP_CONNECT_SRC": ("'self'",),
    "CSP_FRAME_ANCESTORS": ("'none'",),
    "CSP_BASE_URI": ("'self'",),
    "CSP_FORM_ACTION": ("'self'",),
    # Stricter upload limits
    "FILE_UPLOAD_MAX_MEMORY_SIZE": 2621440,  # 2.5 MB
    "DATA_UPLOAD_MAX_MEMORY_SIZE": 5242880,  # 5 MB
    "DATA_UPLOAD_MAX_NUMBER_FIELDS": 100,
    # Additional strict settings
    "SECURE_BROWSER_XSS_FILTER": True,
    "PASSWORD_RESET_TIMEOUT": 3600,  # 1 hour
}


# Moderate preset - Balance between security and flexibility
MODERATE_PRESET = {
    **SECURE_DEFAULTS,
    # Moderate session security
    "SESSION_COOKIE_AGE": 7200,  # 2 hours
    # Moderate CSP - Allow some inline with nonces
    "CSP_DEFAULT_SRC": ("'self'",),
    "CSP_SCRIPT_SRC": ("'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"),
    "CSP_STYLE_SRC": ("'self'", "'unsafe-inline'", "https://fonts.googleapis.com"),
    "CSP_IMG_SRC": ("'self'", "data:", "https:"),
    "CSP_FONT_SRC": ("'self'", "https://fonts.gstatic.com"),
    "CSP_CONNECT_SRC": ("'self'", "https://api.example.com"),
    # Moderate upload limits
    "FILE_UPLOAD_MAX_MEMORY_SIZE": 10485760,  # 10 MB
    "DATA_UPLOAD_MAX_MEMORY_SIZE": 20971520,  # 20 MB
    "DATA_UPLOAD_MAX_NUMBER_FIELDS": 500,
}


# Relaxed preset - For development and testing
RELAXED_PRESET = {
    # Basic security without HTTPS requirements
    "SECURE_SSL_REDIRECT": False,
    "SESSION_COOKIE_SECURE": False,
    "CSRF_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": True,
    "CSRF_COOKIE_HTTPONLY": True,
    # Long sessions for development
    "SESSION_COOKIE_AGE": 86400,  # 24 hours
    "SESSION_EXPIRE_AT_BROWSER_CLOSE": False,
    # Minimal HSTS
    "SECURE_HSTS_SECONDS": 0,
    "SECURE_HSTS_INCLUDE_SUBDOMAINS": False,
    "SECURE_HSTS_PRELOAD": False,
    # Basic security headers
    "SECURE_CONTENT_TYPE_NOSNIFF": True,
    "X_FRAME_OPTIONS": "SAMEORIGIN",  # Allow same-origin frames
    # Permissive CSP
    "CSP_DEFAULT_SRC": (
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "http:",
        "https:",
        "data:",
    ),
    # Relaxed upload limits
    "FILE_UPLOAD_MAX_MEMORY_SIZE": 52428800,  # 50 MB
    "DATA_UPLOAD_MAX_MEMORY_SIZE": 104857600,  # 100 MB
    "DATA_UPLOAD_MAX_NUMBER_FIELDS": 10000,
    # Basic password validation
    "AUTH_PASSWORD_VALIDATORS": [
        {
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
            "OPTIONS": {
                "min_length": 8,
            },
        },
    ],
}


# Development preset (alias for relaxed)
DEV_PRESET = RELAXED_PRESET.copy()


# Test preset - Minimal security for testing
TEST_PRESET = {
    "SECURE_SSL_REDIRECT": False,
    "SESSION_COOKIE_SECURE": False,
    "CSRF_COOKIE_SECURE": False,
    "SECURE_HSTS_SECONDS": 0,
    "AUTH_PASSWORD_VALIDATORS": [],  # No password validation in tests
    "SESSION_COOKIE_AGE": 86400,
    "X_FRAME_OPTIONS": "SAMEORIGIN",
}


# Preset registry
PRESETS = {
    "strict": STRICT_PRESET,
    "moderate": MODERATE_PRESET,
    "relaxed": RELAXED_PRESET,
    "dev": DEV_PRESET,
    "development": DEV_PRESET,
    "test": TEST_PRESET,
    "testing": TEST_PRESET,
    "production": STRICT_PRESET,  # Alias for strict
}


def get_preset(name: str) -> Dict[str, Any]:
    """
    Get a security configuration preset by name.

    Args:
        name: Preset name ('strict', 'moderate', 'relaxed', 'dev', 'test')

    Returns:
        Dictionary containing security configuration

    Raises:
        ValueError: If preset name is not found
    """
    name = name.lower()
    preset = PRESETS.get(name)
    if preset is None:
        available = ", ".join(sorted(PRESETS.keys()))
        raise ValueError(f"Unknown preset: {name}. Available presets: {available}")

    return preset.copy()


def list_presets() -> list:
    """
    List all available presets.

    Returns:
        List of available preset names
    """
    return sorted(PRESETS.keys())


def get_preset_description(name: str) -> str:
    """
    Get a description of a security preset.

    Args:
        name: Preset name

    Returns:
        String description of the preset
    """
    descriptions = {
        "strict": "Maximum security for production environments. Enforces HTTPS, strict CSP, short sessions.",
        "moderate": "Balanced security and flexibility. Good for staging environments.",
        "relaxed": "Minimal security for development. No HTTPS required, permissive CSP.",
        "dev": "Alias for relaxed preset. Use for local development.",
        "development": "Alias for relaxed preset. Use for local development.",
        "test": "Minimal security for testing. Disables most security features.",
        "testing": "Alias for test preset. Use in test environments.",
        "production": "Alias for strict preset. Use in production environments.",
    }

    return descriptions.get(name.lower(), "No description available.")
