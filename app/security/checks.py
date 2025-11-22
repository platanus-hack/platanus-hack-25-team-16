"""
Django System Checks for Security

Provides custom security checks that can be run with:
    python manage.py check --tag security
"""

import os
from django.conf import settings
from django.core.checks import Error, Warning, Info, register


@register("security")
def check_debug_mode(app_configs, **kwargs):
    """Check if DEBUG mode is disabled in production."""
    errors = []

    # Check if running in production-like environment
    is_production = any(
        [
            os.environ.get("DJANGO_ENV") == "production",
            os.environ.get("ENV") == "production",
            os.environ.get("ENVIRONMENT") == "production",
            not settings.DEBUG and settings.ALLOWED_HOSTS,
        ]
    )

    if is_production and settings.DEBUG:
        errors.append(
            Error(
                "DEBUG mode is enabled in production environment",
                hint="Set DEBUG=False in production settings",
                id="security.E001",
            )
        )

    return errors


@register("security")
def check_secret_key(app_configs, **kwargs):
    """Check SECRET_KEY configuration."""
    errors = []

    secret_key = settings.SECRET_KEY

    # Check length
    if len(secret_key) < 50:
        errors.append(
            Error(
                f"SECRET_KEY is too short ({len(secret_key)} characters)",
                hint="Generate a SECRET_KEY with at least 50 characters",
                id="security.E002",
            )
        )

    # Check for default/insecure key
    insecure_patterns = [
        "django-insecure",
        "changeme",
        "secret",
        "default",
        "placeholder",
        "1234567890",
    ]

    for pattern in insecure_patterns:
        if pattern.lower() in secret_key.lower():
            errors.append(
                Error(
                    f"SECRET_KEY contains insecure pattern: {pattern}",
                    hint="Generate a new secure SECRET_KEY",
                    id="security.E003",
                )
            )
            break

    # Check if hardcoded (not from environment)
    if not os.environ.get("SECRET_KEY") and not settings.DEBUG:
        errors.append(
            Warning(
                "SECRET_KEY appears to be hardcoded",
                hint="Consider loading SECRET_KEY from environment variables",
                id="security.W001",
            )
        )

    return errors


@register("security")
def check_allowed_hosts(app_configs, **kwargs):
    """Check ALLOWED_HOSTS configuration."""
    errors = []

    if not settings.DEBUG and not settings.ALLOWED_HOSTS:
        errors.append(
            Error(
                "ALLOWED_HOSTS is empty with DEBUG=False",
                hint="Configure ALLOWED_HOSTS with your domain names",
                id="security.E004",
            )
        )

    # Check for overly permissive hosts
    if "*" in settings.ALLOWED_HOSTS and not settings.DEBUG:
        errors.append(
            Warning(
                "ALLOWED_HOSTS contains wildcard (*)",
                hint="Specify exact domain names instead of wildcards",
                id="security.W002",
            )
        )

    return errors


@register("security")
def check_csrf_configuration(app_configs, **kwargs):
    """Check CSRF protection configuration."""
    errors = []

    # Check CSRF_TRUSTED_ORIGINS
    if not settings.DEBUG and not getattr(settings, "CSRF_TRUSTED_ORIGINS", None):
        errors.append(
            Info(
                "CSRF_TRUSTED_ORIGINS not configured",
                hint="Configure CSRF_TRUSTED_ORIGINS for cross-origin requests",
                id="security.I001",
            )
        )

    # Check if CSRF middleware is enabled
    csrf_middleware = "django.middleware.csrf.CsrfViewMiddleware"
    if csrf_middleware not in settings.MIDDLEWARE:
        errors.append(
            Error(
                "CSRF middleware is not enabled",
                hint=f"Add {csrf_middleware} to MIDDLEWARE",
                id="security.E005",
            )
        )

    # Check cookie settings
    if not settings.DEBUG:
        if not getattr(settings, "CSRF_COOKIE_SECURE", False):
            errors.append(
                Warning(
                    "CSRF_COOKIE_SECURE is False",
                    hint="Set CSRF_COOKIE_SECURE=True for HTTPS sites",
                    id="security.W003",
                )
            )

        if not getattr(settings, "CSRF_COOKIE_HTTPONLY", False):
            errors.append(
                Info(
                    "CSRF_COOKIE_HTTPONLY is False",
                    hint="Consider setting CSRF_COOKIE_HTTPONLY=True",
                    id="security.I002",
                )
            )

    return errors


@register("security")
def check_session_configuration(app_configs, **kwargs):
    """Check session security configuration."""
    errors = []

    if not settings.DEBUG:
        # Check session cookie security
        if not getattr(settings, "SESSION_COOKIE_SECURE", False):
            errors.append(
                Warning(
                    "SESSION_COOKIE_SECURE is False",
                    hint="Set SESSION_COOKIE_SECURE=True for HTTPS sites",
                    id="security.W004",
                )
            )

        if not getattr(settings, "SESSION_COOKIE_HTTPONLY", True):
            errors.append(
                Warning(
                    "SESSION_COOKIE_HTTPONLY is False",
                    hint="Set SESSION_COOKIE_HTTPONLY=True to prevent XSS attacks",
                    id="security.W005",
                )
            )

        # Check session timeout
        session_age = getattr(settings, "SESSION_COOKIE_AGE", 1209600)
        if session_age > 86400:  # More than 24 hours
            errors.append(
                Info(
                    f"Session timeout is very long: {session_age} seconds",
                    hint="Consider reducing SESSION_COOKIE_AGE for better security",
                    id="security.I003",
                )
            )

    return errors


@register("security")
def check_ssl_configuration(app_configs, **kwargs):
    """Check SSL/TLS configuration."""
    errors = []

    if not settings.DEBUG:
        # Check SSL redirect
        if not getattr(settings, "SECURE_SSL_REDIRECT", False):
            errors.append(
                Warning(
                    "SECURE_SSL_REDIRECT is False",
                    hint="Enable SECURE_SSL_REDIRECT to force HTTPS",
                    id="security.W006",
                )
            )

        # Check HSTS
        hsts_seconds = getattr(settings, "SECURE_HSTS_SECONDS", 0)
        if hsts_seconds == 0:
            errors.append(
                Warning(
                    "HSTS is not enabled",
                    hint="Set SECURE_HSTS_SECONDS to enable HSTS",
                    id="security.W007",
                )
            )
        elif hsts_seconds < 31536000:  # Less than 1 year
            errors.append(
                Info(
                    f"HSTS max-age is less than recommended: {hsts_seconds} seconds",
                    hint="Consider setting SECURE_HSTS_SECONDS to 31536000 (1 year)",
                    id="security.I004",
                )
            )

    return errors


@register("security")
def check_security_headers(app_configs, **kwargs):
    """Check security headers configuration."""
    errors = []

    # Check X-Frame-Options
    x_frame = getattr(settings, "X_FRAME_OPTIONS", None)
    if not x_frame:
        errors.append(
            Warning(
                "X_FRAME_OPTIONS not set",
                hint="Set X_FRAME_OPTIONS to prevent clickjacking",
                id="security.W008",
            )
        )

    # Check Content-Type-Options
    if not getattr(settings, "SECURE_CONTENT_TYPE_NOSNIFF", False):
        errors.append(
            Warning(
                "SECURE_CONTENT_TYPE_NOSNIFF is False",
                hint="Set SECURE_CONTENT_TYPE_NOSNIFF=True",
                id="security.W009",
            )
        )

    # Check for security middleware
    security_middleware = "django.middleware.security.SecurityMiddleware"
    if security_middleware not in settings.MIDDLEWARE:
        errors.append(
            Error(
                "Security middleware is not enabled",
                hint=f"Add {security_middleware} to MIDDLEWARE",
                id="security.E006",
            )
        )

    return errors


@register("security")
def check_password_validators(app_configs, **kwargs):
    """Check password validation configuration."""
    errors = []

    validators = getattr(settings, "AUTH_PASSWORD_VALIDATORS", [])

    if not validators:
        errors.append(
            Warning(
                "No password validators configured",
                hint="Configure AUTH_PASSWORD_VALIDATORS for password security",
                id="security.W010",
            )
        )
    else:
        # Check for minimum length validator
        has_length = any(
            "MinimumLengthValidator" in v.get("NAME", "") for v in validators
        )
        if not has_length:
            errors.append(
                Info(
                    "No minimum password length validator",
                    hint="Add MinimumLengthValidator to AUTH_PASSWORD_VALIDATORS",
                    id="security.I005",
                )
            )

    return errors


@register("security")
def check_database_configuration(app_configs, **kwargs):
    """Check database security configuration."""
    errors = []

    # Check for SQLite in production
    if not settings.DEBUG:
        for db_alias, db_config in settings.DATABASES.items():
            if "sqlite" in db_config.get("ENGINE", "").lower():
                errors.append(
                    Warning(
                        f"SQLite database used in production: {db_alias}",
                        hint="Consider using PostgreSQL or MySQL in production",
                        id="security.W011",
                    )
                )

    return errors


@register("security")
def check_file_upload_configuration(app_configs, **kwargs):
    """Check file upload security configuration."""
    errors = []

    # Check upload size limits
    max_upload = getattr(settings, "FILE_UPLOAD_MAX_MEMORY_SIZE", None)
    if max_upload and max_upload > 52428800:  # 50 MB
        errors.append(
            Info(
                f"Large file upload limit: {max_upload} bytes",
                hint="Consider reducing FILE_UPLOAD_MAX_MEMORY_SIZE",
                id="security.I006",
            )
        )

    # Check data upload limits
    max_fields = getattr(settings, "DATA_UPLOAD_MAX_NUMBER_FIELDS", 1000)
    if max_fields > 10000:
        errors.append(
            Info(
                f"High field limit: {max_fields}",
                hint="Consider reducing DATA_UPLOAD_MAX_NUMBER_FIELDS",
                id="security.I007",
            )
        )

    return errors


# Summary function for all checks
def run_security_checks():
    """
    Run all security checks and return results.

    Usage:
        from app.security.checks import run_security_checks
        results = run_security_checks()
    """
    from django.core.checks import run_checks

    return run_checks(tags=["security"])
