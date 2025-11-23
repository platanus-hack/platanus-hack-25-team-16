"""
Security Settings Configuration

Provides secure default configurations for Django projects.
These settings are designed to maximize security while maintaining flexibility.
"""

import warnings
from typing import Any, Dict

# Secure defaults dictionary - Best practices for Django security
SECURE_DEFAULTS = {
    # SSL/TLS Configuration
    "SECURE_SSL_REDIRECT": False,  # Force HTTPS in production
    "SECURE_PROXY_SSL_HEADER": ("HTTP_X_FORWARDED_PROTO", "https"),
    # Cookie Security
    "SESSION_COOKIE_SECURE": True,  # Cookies only over HTTPS
    "SESSION_COOKIE_HTTPONLY": True,  # Prevent JavaScript access
    "SESSION_COOKIE_SAMESITE": "Strict",  # CSRF protection
    "SESSION_COOKIE_AGE": 3600,  # 1 hour session timeout
    "SESSION_EXPIRE_AT_BROWSER_CLOSE": True,
    "CSRF_COOKIE_SECURE": True,
    "CSRF_COOKIE_HTTPONLY": True,
    "CSRF_COOKIE_SAMESITE": "Strict",
    "CSRF_USE_SESSIONS": False,  # Store CSRF token in cookie, not session
    # Security Headers
    "SECURE_HSTS_SECONDS": 31536000,  # 1 year
    "SECURE_HSTS_INCLUDE_SUBDOMAINS": True,
    "SECURE_HSTS_PRELOAD": True,
    "SECURE_CONTENT_TYPE_NOSNIFF": True,
    "SECURE_BROWSER_XSS_FILTER": True,  # Legacy browsers
    "SECURE_REFERRER_POLICY": "strict-origin-when-cross-origin",
    # X-Frame-Options
    "X_FRAME_OPTIONS": "DENY",
    # Content Security Policy (basic)
    "CSP_DEFAULT_SRC": ("'self'",),
    "CSP_SCRIPT_SRC": ("'self'", "'unsafe-inline'"),  # Can be stricter
    "CSP_STYLE_SRC": ("'self'", "'unsafe-inline'"),  # Can be stricter
    # File Upload Security
    "FILE_UPLOAD_MAX_MEMORY_SIZE": 5242880,  # 5 MB
    "DATA_UPLOAD_MAX_MEMORY_SIZE": 10485760,  # 10 MB
    "DATA_UPLOAD_MAX_NUMBER_FIELDS": 1000,
    # Password Security
    "AUTH_PASSWORD_VALIDATORS": [
        {
            "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
            "OPTIONS": {
                "min_length": 12,
            },
        },
        {
            "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
        },
    ],
    # Other Security Settings
    "USE_X_FORWARDED_HOST": False,
    "USE_X_FORWARDED_PORT": False,
    "DEFAULT_AUTO_FIELD": "django.db.models.BigAutoField",
    # Logging
    "SECURE_LOGGING_ENABLED": True,
}


def apply_secure_defaults(settings_dict: Dict[str, Any], preset: str = None) -> None:
    """
    Apply secure defaults to Django settings.

    Args:
        settings_dict: Dictionary containing Django settings (usually globals())
        preset: Optional preset name ('strict', 'moderate', 'relaxed')

    Example:
        # In settings.py
        from app.security.conf import apply_secure_defaults
        apply_secure_defaults(globals())
    """
    from .presets import get_preset

    # If preset is provided, use preset configuration
    if preset:
        config = get_preset(preset)
    else:
        config = SECURE_DEFAULTS.copy()

    # Check if we're in DEBUG mode
    debug_mode = settings_dict.get("DEBUG", False)

    if debug_mode:
        # In DEBUG mode, apply development-friendly settings
        warnings.warn(
            "Security: Running in DEBUG mode. Some security features are disabled for development.",
            UserWarning,
        )

        # Override some settings for development
        config.update(
            {
                "SECURE_SSL_REDIRECT": False,
                "SESSION_COOKIE_SECURE": False,
                "CSRF_COOKIE_SECURE": False,
                "SECURE_HSTS_SECONDS": 0,
            }
        )

    # Apply the configuration
    for key, value in config.items():
        # Don't override existing settings unless they're explicitly None
        if key not in settings_dict or settings_dict[key] is None:
            settings_dict[key] = value

    # Ensure MIDDLEWARE is a list for modification
    if "MIDDLEWARE" not in settings_dict:
        settings_dict["MIDDLEWARE"] = []

    # Add security middleware if not present
    security_middleware = [
        "django.middleware.security.SecurityMiddleware",
        "app.security.middleware.security_headers.SecurityHeadersMiddleware",
        "app.security.middleware.rate_limiting.RateLimitingMiddleware",
        "app.security.middleware.request_size_limit.RequestSizeLimitMiddleware",
        "app.security.middleware.suspicious_patterns.SuspiciousPatternsMiddleware",
    ]

    # Insert security middleware at the beginning
    middleware_list = list(settings_dict["MIDDLEWARE"])
    for mw in reversed(security_middleware):
        if mw not in middleware_list:
            # Insert after SecurityMiddleware if it exists, otherwise at the beginning
            if "django.middleware.security.SecurityMiddleware" in middleware_list:
                idx = (
                    middleware_list.index(
                        "django.middleware.security.SecurityMiddleware"
                    )
                    + 1
                )
                middleware_list.insert(idx, mw)
            else:
                middleware_list.insert(0, mw)

    settings_dict["MIDDLEWARE"] = middleware_list


def validate_security_configuration(settings_dict: Dict[str, Any]) -> list:
    """
    Validate security configuration and return warnings/errors.

    Args:
        settings_dict: Dictionary containing Django settings

    Returns:
        List of validation messages
    """
    messages = []

    # Check DEBUG in production
    if settings_dict.get("DEBUG", False):
        messages.append(
            "WARNING: DEBUG is enabled. This should be False in production."
        )

    # Check SECRET_KEY
    secret_key = settings_dict.get("SECRET_KEY", "")
    if len(secret_key) < 50:
        messages.append("ERROR: SECRET_KEY should be at least 50 characters long.")
    if "django-insecure" in secret_key:
        messages.append("ERROR: Using default insecure SECRET_KEY. Generate a new one.")

    # Check ALLOWED_HOSTS
    if not settings_dict.get("ALLOWED_HOSTS"):
        messages.append("WARNING: ALLOWED_HOSTS is empty. Configure for production.")

    # Check SSL redirect
    if not settings_dict.get("SECURE_SSL_REDIRECT", False) and not settings_dict.get(
        "DEBUG"
    ):
        messages.append("WARNING: SECURE_SSL_REDIRECT is False in non-DEBUG mode.")

    # Check CSRF configuration
    if not settings_dict.get("CSRF_TRUSTED_ORIGINS") and not settings_dict.get("DEBUG"):
        messages.append(
            "INFO: Consider setting CSRF_TRUSTED_ORIGINS for cross-origin requests."
        )

    return messages
