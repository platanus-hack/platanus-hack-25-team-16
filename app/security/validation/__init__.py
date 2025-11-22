"""
Security Validation Module
"""

from .input_validators import (
    InputValidator,
    validate_input,
    SecureSerializer,
    SecureModelSerializer,
    is_safe_string,
    clean_input,
)

from .output_encoding import (
    sanitize_html,
    escape_html,
    escape_js,
    escape_json,
    escape_url,
    safe_json_response,
    safe_update,
    safe_filter,
    safe_html_filter,
    safe_json_filter,
    safe_url_filter,
    strip_tags,
    truncate_html,
    normalize_whitespace,
)

__all__ = [
    # Input validation
    "InputValidator",
    "validate_input",
    "SecureSerializer",
    "SecureModelSerializer",
    "is_safe_string",
    "clean_input",
    # Output encoding
    "sanitize_html",
    "escape_html",
    "escape_js",
    "escape_json",
    "escape_url",
    "safe_json_response",
    "safe_update",
    "safe_filter",
    "safe_html_filter",
    "safe_json_filter",
    "safe_url_filter",
    "strip_tags",
    "truncate_html",
    "normalize_whitespace",
]
