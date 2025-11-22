from django.apps import AppConfig


class InputValidationConfig(AppConfig):
    """
    Configuration for the Input Validation app.

    This app provides:
    - Custom validators for preventing XSS, SQL injection, command injection, etc.
    - Sanitizers for cleaning user input
    - Secure serializers for Django REST Framework
    - Middleware for automatic request sanitization and security headers
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'input_validation'
    verbose_name = 'Input Validation & Sanitization'
