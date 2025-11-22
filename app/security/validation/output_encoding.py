"""
Output Encoding and Sanitization Module

Provides functions to safely encode and sanitize output to prevent XSS attacks.
"""

import html
import json
import re
from typing import Any, Dict, List, Optional, Set
from django.utils.safestring import mark_safe


# Default allowed HTML tags and attributes for sanitization
DEFAULT_ALLOWED_TAGS = {
    "a",
    "abbr",
    "acronym",
    "b",
    "blockquote",
    "code",
    "em",
    "i",
    "li",
    "ol",
    "p",
    "strong",
    "ul",
    "br",
    "span",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
}

DEFAULT_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target"],
    "abbr": ["title"],
    "acronym": ["title"],
    "table": ["class"],
    "td": ["colspan", "rowspan"],
    "th": ["colspan", "rowspan"],
    "span": ["class"],
    "div": ["class", "id"],
}


def sanitize_html(
    content: str,
    allowed_tags: Optional[Set[str]] = None,
    allowed_attributes: Optional[Dict[str, List[str]]] = None,
    strip: bool = True,
) -> str:
    """
    Sanitize HTML content by removing dangerous tags and attributes.

    Args:
        content: HTML content to sanitize
        allowed_tags: Set of allowed HTML tags
        allowed_attributes: Dict of allowed attributes per tag
        strip: Whether to strip disallowed tags or escape them

    Returns:
        Sanitized HTML content
    """
    if not content:
        return ""

    # Use defaults if not provided
    if allowed_tags is None:
        allowed_tags = DEFAULT_ALLOWED_TAGS
    if allowed_attributes is None:
        allowed_attributes = DEFAULT_ALLOWED_ATTRIBUTES

    try:
        import bleach

        # Use bleach if available for robust sanitization
        clean_content = bleach.clean(
            content,
            tags=list(allowed_tags),
            attributes=allowed_attributes,
            strip=strip,
            protocols=["http", "https", "mailto"],
        )
        return clean_content
    except ImportError:
        # Fallback to basic sanitization if bleach is not available
        return basic_sanitize_html(content, allowed_tags)


def basic_sanitize_html(content: str, allowed_tags: Set[str]) -> str:
    """
    Basic HTML sanitization without external libraries.

    Args:
        content: HTML content to sanitize
        allowed_tags: Set of allowed HTML tags

    Returns:
        Sanitized HTML content
    """
    # Remove script tags and their content
    content = re.sub(
        r"<script[^>]*>.*?</script>", "", content, flags=re.IGNORECASE | re.DOTALL
    )

    # Remove style tags and their content
    content = re.sub(
        r"<style[^>]*>.*?</style>", "", content, flags=re.IGNORECASE | re.DOTALL
    )

    # Remove javascript: and data: URLs
    content = re.sub(r"(javascript|data):", "", content, flags=re.IGNORECASE)

    # Remove event handlers
    content = re.sub(
        r'\s*on\w+\s*=\s*["\'][^"\']*["\']', "", content, flags=re.IGNORECASE
    )
    content = re.sub(r"\s*on\w+\s*=\s*[^\s>]+", "", content, flags=re.IGNORECASE)

    # Remove dangerous attributes
    dangerous_attrs = [
        "onclick",
        "onload",
        "onerror",
        "onmouseover",
        "onfocus",
        "onblur",
    ]
    for attr in dangerous_attrs:
        content = re.sub(
            rf'\s*{attr}\s*=\s*["\'][^"\']*["\']', "", content, flags=re.IGNORECASE
        )

    # Escape HTML for tags not in allowed list
    if allowed_tags:
        # This is a simplified approach - for production use bleach
        for tag in re.findall(r"<(\w+)[^>]*>", content):
            if tag.lower() not in allowed_tags:
                content = content.replace(f"<{tag}", f"&lt;{tag}")
                content = content.replace(f"</{tag}>", f"&lt;/{tag}&gt;")

    return content


def escape_html(text: str) -> str:
    """
    Escape HTML special characters.

    Args:
        text: Text to escape

    Returns:
        HTML-escaped text
    """
    return html.escape(text)


def escape_js(text: str) -> str:
    """
    Escape text for safe inclusion in JavaScript.

    Args:
        text: Text to escape

    Returns:
        JavaScript-escaped text
    """
    if not text:
        return ""

    # Escape special JavaScript characters
    replacements = {
        "\\": "\\\\",
        '"': '\\"',
        "'": "\\'",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "<": "\\u003c",  # Prevent </script> injection
        ">": "\\u003e",
        "/": "\\/",  # Prevent regex injection
    }

    for char, replacement in replacements.items():
        text = text.replace(char, replacement)

    return text


def escape_json(obj: Any) -> str:
    """
    Safely encode object as JSON for inclusion in HTML.

    Args:
        obj: Object to encode

    Returns:
        JSON string safe for HTML inclusion
    """
    json_str = json.dumps(obj, ensure_ascii=True)
    # Escape for safe inclusion in HTML
    json_str = json_str.replace("<", "\\u003c")
    json_str = json_str.replace(">", "\\u003e")
    json_str = json_str.replace("&", "\\u0026")
    return json_str


def escape_url(url: str) -> str:
    """
    Escape URL for safe inclusion in HTML attributes.

    Args:
        url: URL to escape

    Returns:
        Escaped URL
    """
    if not url:
        return ""

    # Block dangerous protocols
    dangerous_protocols = ["javascript:", "data:", "vbscript:"]
    lower_url = url.lower().strip()

    for protocol in dangerous_protocols:
        if lower_url.startswith(protocol):
            return ""  # Return empty string for dangerous URLs

    # HTML escape the URL
    return html.escape(url)


def safe_json_response(data: Any, exclude_fields: Optional[List[str]] = None) -> Dict:
    """
    Prepare data for safe JSON response.

    Args:
        data: Data to sanitize
        exclude_fields: Fields to exclude from response

    Returns:
        Sanitized data dictionary
    """
    if exclude_fields is None:
        exclude_fields = ["password", "token", "secret", "api_key", "private_key"]

    def sanitize_dict(obj: Dict) -> Dict:
        """Recursively sanitize dictionary."""
        sanitized = {}
        for key, value in obj.items():
            # Skip excluded fields
            if any(excluded in key.lower() for excluded in exclude_fields):
                continue

            # Recursively sanitize nested structures
            if isinstance(value, dict):
                sanitized[key] = sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    sanitize_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            elif isinstance(value, str):
                # Escape HTML in string values
                sanitized[key] = escape_html(value)
            else:
                sanitized[key] = value

        return sanitized

    if isinstance(data, dict):
        return sanitize_dict(data)
    elif isinstance(data, list):
        return [
            sanitize_dict(item) if isinstance(item, dict) else item for item in data
        ]
    else:
        return data


def safe_update(
    instance: Any, data: Dict[str, Any], allowed_fields: Optional[List[str]] = None
) -> Any:
    """
    Safely update model instance to prevent mass assignment.

    Args:
        instance: Model instance to update
        data: Update data
        allowed_fields: List of allowed fields to update

    Returns:
        Updated instance
    """
    if allowed_fields is None:
        # Get model fields excluding sensitive ones
        sensitive_fields = {
            "id",
            "pk",
            "password",
            "is_superuser",
            "is_staff",
            "is_active",
            "date_joined",
            "last_login",
            "user_permissions",
            "groups",
            "created_at",
            "updated_at",
        }

        if hasattr(instance, "_meta"):
            model_fields = [f.name for f in instance._meta.fields]
            allowed_fields = [f for f in model_fields if f not in sensitive_fields]
        else:
            allowed_fields = []

    # Update only allowed fields
    for field, value in data.items():
        if field in allowed_fields:
            setattr(instance, field, value)

    return instance


def safe_filter(
    queryset, params: Dict[str, Any], allowed_fields: Optional[List[str]] = None
) -> Any:
    """
    Safely filter queryset to prevent unauthorized access.

    Args:
        queryset: Django queryset
        params: Filter parameters
        allowed_fields: List of allowed filter fields

    Returns:
        Filtered queryset
    """
    if allowed_fields is None:
        # Default to common safe fields
        allowed_fields = ["id", "name", "slug", "status", "created_at", "updated_at"]

    # Build safe filter dict
    safe_params = {}
    for field, value in params.items():
        # Remove any field lookups (e.g., field__contains)
        base_field = field.split("__")[0]

        if base_field in allowed_fields:
            # Validate value type
            if isinstance(value, (str, int, float, bool, type(None))):
                safe_params[field] = value
            elif isinstance(value, list):
                # Ensure list contains only safe types
                if all(isinstance(v, (str, int, float, bool)) for v in value):
                    safe_params[field] = value

    return queryset.filter(**safe_params)


# Template filters for Django templates
def safe_html_filter(value: str) -> str:
    """Django template filter for safe HTML output."""
    return mark_safe(sanitize_html(value))


def safe_json_filter(value: Any) -> str:
    """Django template filter for safe JSON output."""
    return mark_safe(escape_json(value))


def safe_url_filter(value: str) -> str:
    """Django template filter for safe URL output."""
    return escape_url(value)


# Convenience functions
def strip_tags(value: str) -> str:
    """Remove all HTML tags from text."""
    return re.sub(r"<[^>]+>", "", value)


def truncate_html(value: str, length: int = 100, suffix: str = "...") -> str:
    """
    Truncate HTML content while preserving valid HTML.

    Args:
        value: HTML content
        length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        Truncated HTML
    """
    if not value or len(value) <= length:
        return value

    # Use Django's truncator if available
    try:
        from django.utils.text import Truncator

        return Truncator(value).chars(length, html=True)
    except ImportError:
        # Fallback to simple truncation
        text_only = strip_tags(value)
        if len(text_only) > length:
            return text_only[: length - len(suffix)] + suffix
        return value


def normalize_whitespace(value: str) -> str:
    """Normalize whitespace in text."""
    # Replace multiple spaces with single space
    value = re.sub(r"\s+", " ", value)
    # Remove leading/trailing whitespace
    return value.strip()
