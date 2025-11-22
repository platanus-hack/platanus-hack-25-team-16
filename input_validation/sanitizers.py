"""
Input sanitization utilities.

This module provides functions to clean and sanitize user input to prevent:
- XSS attacks
- SQL injection
- HTML injection
- Path traversal
- Command injection
"""

import html
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, unquote


class InputSanitizer:
    """
    Main sanitizer class for cleaning user input.
    """

    @staticmethod
    def sanitize_html(value: str, strip_tags: bool = True) -> str:
        """
        Sanitize HTML content to prevent XSS attacks.

        Args:
            value: Input string to sanitize
            strip_tags: If True, remove all HTML tags; if False, escape them

        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value

        if strip_tags:
            # Remove all HTML tags
            value = re.sub(r'<[^>]+>', '', value)
        else:
            # Escape HTML special characters
            value = html.escape(value)

        # Remove null bytes
        value = value.replace('\x00', '')

        return value

    @staticmethod
    def sanitize_sql(value: str) -> str:
        """
        Sanitize input to prevent SQL injection.

        Note: This is a defense-in-depth measure. Always use parameterized queries.

        Args:
            value: Input string to sanitize

        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value

        # Remove SQL comments
        value = re.sub(r'(--|#|\/\*|\*\/)', '', value)

        # Remove null bytes
        value = value.replace('\x00', '')

        # Escape single quotes (doubling them is SQL-safe)
        value = value.replace("'", "''")

        return value

    @staticmethod
    def sanitize_path(value: str) -> str:
        """
        Sanitize file paths to prevent directory traversal.

        Args:
            value: Input path to sanitize

        Returns:
            Sanitized path
        """
        if not isinstance(value, str):
            return value

        # Remove null bytes
        value = value.replace('\x00', '')

        # Remove parent directory references
        value = value.replace('..', '')

        # Remove absolute path indicators
        value = value.lstrip('/')
        value = value.lstrip('\\')

        # Remove home directory references
        value = value.replace('~/', '')
        value = value.replace('~\\', '')

        # Normalize slashes
        value = value.replace('\\', '/')

        return value

    @staticmethod
    def sanitize_shell(value: str) -> str:
        """
        Sanitize input to prevent command injection.

        Args:
            value: Input string to sanitize

        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value

        # Remove shell metacharacters
        dangerous_chars = ['&', '|', ';', '$', '`', '\n', '\r', '(', ')', '<', '>', '\\']
        for char in dangerous_chars:
            value = value.replace(char, '')

        # Remove null bytes
        value = value.replace('\x00', '')

        return value

    @staticmethod
    def sanitize_email(value: str) -> str:
        """
        Sanitize email addresses to prevent injection attacks.

        Args:
            value: Email address to sanitize

        Returns:
            Sanitized email
        """
        if not isinstance(value, str):
            return value

        # Remove whitespace
        value = value.strip()

        # Convert to lowercase
        value = value.lower()

        # Remove null bytes
        value = value.replace('\x00', '')

        # Remove newlines and carriage returns (header injection prevention)
        value = value.replace('\n', '').replace('\r', '')

        # Remove URL-encoded newlines
        value = value.replace('%0a', '').replace('%0d', '')

        return value

    @staticmethod
    def sanitize_url(value: str) -> str:
        """
        Sanitize URLs to prevent injection attacks.

        Args:
            value: URL to sanitize

        Returns:
            Sanitized URL
        """
        if not isinstance(value, str):
            return value

        # Remove whitespace
        value = value.strip()

        # Remove null bytes
        value = value.replace('\x00', '')

        # Remove newlines
        value = value.replace('\n', '').replace('\r', '')

        # Decode URL encoding to check for hidden characters
        decoded = unquote(value)

        # Re-encode to normalize
        # This helps prevent double-encoding attacks
        value = quote(decoded, safe=':/?#[]@!$&\'()*+,;=')

        return value

    @staticmethod
    def sanitize_username(value: str) -> str:
        """
        Sanitize usernames to allow only safe characters.

        Args:
            value: Username to sanitize

        Returns:
            Sanitized username
        """
        if not isinstance(value, str):
            return value

        # Remove whitespace
        value = value.strip()

        # Convert to lowercase
        value = value.lower()

        # Remove non-alphanumeric characters except underscore and hyphen
        value = re.sub(r'[^a-z0-9_-]', '', value)

        # Remove null bytes
        value = value.replace('\x00', '')

        return value

    @staticmethod
    def sanitize_phone(value: str) -> str:
        """
        Sanitize phone numbers to contain only digits and +.

        Args:
            value: Phone number to sanitize

        Returns:
            Sanitized phone number
        """
        if not isinstance(value, str):
            return value

        # Remove whitespace
        value = value.strip()

        # Keep only digits and +
        value = re.sub(r'[^0-9+]', '', value)

        # Ensure only one + at the beginning
        if '+' in value:
            parts = value.split('+')
            value = '+' + ''.join(parts)

        return value

    @staticmethod
    def sanitize_integer(value: Any, min_value: Optional[int] = None, max_value: Optional[int] = None) -> Optional[int]:
        """
        Sanitize and validate integer input.

        Args:
            value: Value to sanitize
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            Sanitized integer or None if invalid
        """
        try:
            result = int(value)

            if min_value is not None and result < min_value:
                return None

            if max_value is not None and result > max_value:
                return None

            return result
        except (ValueError, TypeError):
            return None

    @staticmethod
    def sanitize_alphanumeric(value: str, allow_spaces: bool = False) -> str:
        """
        Sanitize input to contain only alphanumeric characters.

        Args:
            value: Input to sanitize
            allow_spaces: Whether to allow spaces

        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return value

        if allow_spaces:
            value = re.sub(r'[^a-zA-Z0-9\s]', '', value)
        else:
            value = re.sub(r'[^a-zA-Z0-9]', '', value)

        # Remove null bytes
        value = value.replace('\x00', '')

        return value

    @staticmethod
    def truncate(value: str, max_length: int, suffix: str = '...') -> str:
        """
        Truncate string to maximum length.

        Args:
            value: String to truncate
            max_length: Maximum length
            suffix: Suffix to add if truncated

        Returns:
            Truncated string
        """
        if not isinstance(value, str):
            return value

        if len(value) <= max_length:
            return value

        return value[:max_length - len(suffix)] + suffix


class DictSanitizer:
    """
    Sanitizer for dictionary data (useful for JSON payloads).
    """

    def __init__(
        self,
        html_fields: Optional[List[str]] = None,
        email_fields: Optional[List[str]] = None,
        url_fields: Optional[List[str]] = None,
        strip_tags: bool = True,
    ):
        """
        Initialize DictSanitizer with field-specific sanitization rules.

        Args:
            html_fields: List of field names that should be HTML-sanitized
            email_fields: List of field names that should be email-sanitized
            url_fields: List of field names that should be URL-sanitized
            strip_tags: Whether to strip or escape HTML tags
        """
        self.html_fields = html_fields or []
        self.email_fields = email_fields or []
        self.url_fields = url_fields or []
        self.strip_tags = strip_tags
        self.sanitizer = InputSanitizer()

    def sanitize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize dictionary data according to configured rules.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data

        result = {}

        for key, value in data.items():
            # Recursively sanitize nested dictionaries
            if isinstance(value, dict):
                result[key] = self.sanitize(value)

            # Recursively sanitize lists
            elif isinstance(value, list):
                result[key] = [
                    self.sanitize(item) if isinstance(item, dict) else self._sanitize_value(key, item)
                    for item in value
                ]

            # Sanitize individual values
            else:
                result[key] = self._sanitize_value(key, value)

        return result

    def _sanitize_value(self, key: str, value: Any) -> Any:
        """
        Sanitize a single value based on its field name.

        Args:
            key: Field name
            value: Value to sanitize

        Returns:
            Sanitized value
        """
        if not isinstance(value, str):
            return value

        # Apply field-specific sanitization
        if key in self.email_fields:
            return self.sanitizer.sanitize_email(value)

        elif key in self.url_fields:
            return self.sanitizer.sanitize_url(value)

        elif key in self.html_fields:
            return self.sanitizer.sanitize_html(value, strip_tags=self.strip_tags)

        # Default: basic HTML sanitization
        return self.sanitizer.sanitize_html(value, strip_tags=True)


def sanitize_request_data(
    data: Union[Dict[str, Any], List[Any]],
    html_fields: Optional[List[str]] = None,
    email_fields: Optional[List[str]] = None,
    url_fields: Optional[List[str]] = None,
) -> Union[Dict[str, Any], List[Any]]:
    """
    Convenience function to sanitize request data (dict or list).

    Args:
        data: Data to sanitize
        html_fields: List of field names that should be HTML-sanitized
        email_fields: List of field names that should be email-sanitized
        url_fields: List of field names that should be URL-sanitized

    Returns:
        Sanitized data
    """
    sanitizer = DictSanitizer(
        html_fields=html_fields,
        email_fields=email_fields,
        url_fields=url_fields,
    )

    if isinstance(data, dict):
        return sanitizer.sanitize(data)

    elif isinstance(data, list):
        return [
            sanitizer.sanitize(item) if isinstance(item, dict) else item
            for item in data
        ]

    return data
