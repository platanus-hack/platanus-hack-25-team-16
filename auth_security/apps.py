"""Auth Security app configuration."""

from django.apps import AppConfig


class AuthSecurityConfig(AppConfig):
    """App configuration for auth_security."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "auth_security"
    verbose_name = "Auth Security - Authentication & Sessions"

    def ready(self):
        """Import signals when the app is ready."""
        # Import signals to register them
        from . import signals  # noqa: F401

        # Import axes extension to register signal handlers
        from .middleware import axes_extension  # noqa: F401
