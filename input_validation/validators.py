"""
Custom validators for input validation and sanitization.

This module provides Django REST Framework validators for:
- Email validation
- URL validation
- Phone number validation
- Username validation
- SQL injection prevention
- XSS prevention
- Command injection prevention
"""

import re
from typing import Any
from urllib.parse import urlparse

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator as DjangoEmailValidator
from django.utils.translation import gettext_lazy as _


class StrictEmailValidator(DjangoEmailValidator):
    """
    Enhanced email validator with additional security checks.

    Prevents:
    - Email header injection
    - Multiple @ symbols
    - Suspicious patterns
    """

    # Patterns that might indicate injection attempts
    SUSPICIOUS_PATTERNS = [
        r'[\r\n]',  # Newlines (email header injection)
        r'%0[ad]',  # URL-encoded newlines
        r'bcc:',    # BCC injection attempts
        r'cc:',     # CC injection attempts
        r'to:',     # TO injection attempts
        r'content-type:',  # Header injection
    ]

    def __call__(self, value: str) -> None:
        # First run Django's standard email validation
        super().__call__(value)

        # Additional security checks
        lower_value = value.lower()

        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, lower_value, re.IGNORECASE):
                raise ValidationError(
                    _('Email contains invalid characters or patterns.'),
                    code='invalid_email_pattern'
                )

        # Check for multiple @ symbols (only 1 allowed)
        if value.count('@') != 1:
            raise ValidationError(
                _('Email must contain exactly one @ symbol.'),
                code='invalid_email_format'
            )

        # Check email length (reasonable limit)
        if len(value) > 254:  # RFC 5321
            raise ValidationError(
                _('Email address is too long.'),
                code='email_too_long'
            )


class UsernameValidator:
    """
    Validates usernames to prevent injection attacks and ensure consistency.

    Rules:
    - Alphanumeric characters, underscores, and hyphens only
    - 3-30 characters length
    - Must start with a letter
    - Cannot end with hyphen or underscore
    """

    message = _(
        'Username must be 3-30 characters long, start with a letter, '
        'and contain only letters, numbers, underscores, and hyphens.'
    )
    code = 'invalid_username'

    # Reserved usernames that cannot be used
    RESERVED_USERNAMES = {
        'admin', 'root', 'administrator', 'system', 'sys', 'api',
        'www', 'ftp', 'mail', 'smtp', 'postmaster', 'webmaster',
        'hostmaster', 'nobody', 'anonymous', 'guest', 'null', 'undefined',
    }

    USERNAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$')

    def __call__(self, value: str) -> None:
        # Check pattern
        if not self.USERNAME_PATTERN.match(value):
            raise ValidationError(self.message, code=self.code)

        # Check if it ends with hyphen or underscore
        if value.endswith('-') or value.endswith('_'):
            raise ValidationError(
                _('Username cannot end with a hyphen or underscore.'),
                code='invalid_username_ending'
            )

        # Check reserved usernames
        if value.lower() in self.RESERVED_USERNAMES:
            raise ValidationError(
                _('This username is reserved and cannot be used.'),
                code='reserved_username'
            )


class NoSQLInjectionValidator:
    """
    Validates input to prevent SQL injection attacks.

    Checks for common SQL injection patterns.
    """

    SQL_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|#|\/\*|\*\/)",  # SQL comments
        r"('|(--|#|\/\*))",   # String terminators
        r"(\bOR\b.*=.*)",     # OR conditions
        r"(\bAND\b.*=.*)",    # AND conditions
        r"(\bUNION\b.*\bSELECT\b)",  # UNION queries
        r"(;.*\b(DROP|DELETE|UPDATE|INSERT)\b)",  # Chained queries
        r"(\bEXEC(\s|\+)+(s|x)p\w+)",  # Stored procedures
    ]

    message = _('Input contains potentially malicious SQL patterns.')
    code = 'sql_injection_attempt'

    def __call__(self, value: Any) -> None:
        if not isinstance(value, str):
            return

        # Check each pattern
        for pattern in self.SQL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(self.message, code=self.code)


class NoXSSValidator:
    """
    Validates input to prevent Cross-Site Scripting (XSS) attacks.

    Checks for common XSS patterns and HTML/JavaScript injection.
    """

    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',                 # JavaScript protocol
        r'on\w+\s*=',                  # Event handlers (onclick, onload, etc.)
        r'<iframe[^>]*>',              # IFrames
        r'<object[^>]*>',              # Objects
        r'<embed[^>]*>',               # Embeds
        r'<applet[^>]*>',              # Applets
        r'eval\s*\(',                  # eval()
        r'expression\s*\(',            # CSS expressions
        r'vbscript:',                  # VBScript protocol
        r'data:text/html',             # Data URLs
    ]

    message = _('Input contains potentially malicious HTML or JavaScript.')
    code = 'xss_attempt'

    def __call__(self, value: Any) -> None:
        if not isinstance(value, str):
            return

        # Check each pattern
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(self.message, code=self.code)


class NoCommandInjectionValidator:
    """
    Validates input to prevent command injection attacks.

    Checks for shell metacharacters and command chaining.
    """

    # Shell metacharacters and operators
    SHELL_PATTERNS = [
        r'[;&|`$]',           # Command separators and substitution
        r'\$\{',              # Variable substitution
        r'\$\(',              # Command substitution
        r'>\s*&',             # Output redirection
        r'<\s*&',             # Input redirection
        r'\|\|',              # OR operator
        r'&&',                # AND operator
        r'\.\.',              # Directory traversal
    ]

    message = _('Input contains potentially malicious command patterns.')
    code = 'command_injection_attempt'

    def __call__(self, value: Any) -> None:
        if not isinstance(value, str):
            return

        # Check each pattern
        for pattern in self.SHELL_PATTERNS:
            if re.search(pattern, value):
                raise ValidationError(self.message, code=self.code)


class SafeURLValidator:
    """
    Validates URLs to prevent SSRF and other URL-based attacks.

    Rules:
    - Only allows http:// and https:// protocols
    - Blocks private IP ranges
    - Blocks localhost/loopback addresses
    - Validates URL structure
    """

    message = _('Invalid or unsafe URL.')
    code = 'invalid_url'

    # Private IP ranges (IPv4)
    PRIVATE_IP_PATTERNS = [
        r'^10\.',                      # 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # 172.16.0.0/12
        r'^192\.168\.',                # 192.168.0.0/16
        r'^127\.',                     # 127.0.0.0/8 (loopback)
        r'^169\.254\.',                # 169.254.0.0/16 (link-local)
        r'^0\.',                       # 0.0.0.0/8
    ]

    LOCALHOST_PATTERNS = [
        'localhost',
        '0.0.0.0',
        '::1',
        '[::]',
    ]

    def __call__(self, value: str) -> None:
        if not value:
            raise ValidationError(self.message, code=self.code)

        try:
            parsed = urlparse(value)
        except Exception:
            raise ValidationError(self.message, code=self.code)

        # Check protocol
        if parsed.scheme not in ('http', 'https'):
            raise ValidationError(
                _('Only HTTP and HTTPS protocols are allowed.'),
                code='invalid_protocol'
            )

        # Check hostname exists
        if not parsed.netloc:
            raise ValidationError(
                _('URL must include a hostname.'),
                code='missing_hostname'
            )

        # Extract hostname (remove port if present)
        hostname = parsed.netloc.split(':')[0].lower()

        # Check for localhost
        if hostname in self.LOCALHOST_PATTERNS:
            raise ValidationError(
                _('URLs pointing to localhost are not allowed.'),
                code='localhost_not_allowed'
            )

        # Check for private IP ranges
        for pattern in self.PRIVATE_IP_PATTERNS:
            if re.match(pattern, hostname):
                raise ValidationError(
                    _('URLs pointing to private IP addresses are not allowed.'),
                    code='private_ip_not_allowed'
                )


class PhoneNumberValidator:
    """
    Validates phone numbers in international format.

    Accepts: +[country code][number]
    Example: +1234567890
    """

    message = _(
        'Phone number must be in international format (e.g., +1234567890). '
        'Only digits are allowed after the + symbol.'
    )
    code = 'invalid_phone'

    PHONE_PATTERN = re.compile(r'^\+[1-9]\d{6,14}$')

    def __call__(self, value: str) -> None:
        if not self.PHONE_PATTERN.match(value):
            raise ValidationError(self.message, code=self.code)


class NoPathTraversalValidator:
    """
    Validates file paths to prevent directory traversal attacks.

    Blocks patterns like ../, ..\\, etc.
    """

    TRAVERSAL_PATTERNS = [
        r'\.\.',              # Parent directory
        r'~/',                # Home directory
        r'%2e%2e',           # URL-encoded ..
        r'\.\./',            # ../
        r'\.\.\\'            # ..\
    ]

    message = _('Path contains invalid or unsafe patterns.')
    code = 'path_traversal_attempt'

    def __call__(self, value: str) -> None:
        # Check each pattern
        for pattern in self.TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(self.message, code=self.code)


class ContentLengthValidator:
    """
    Validates content length to prevent DoS attacks via large inputs.
    """

    def __init__(self, max_length: int = 10000):
        self.max_length = max_length

    def __call__(self, value: Any) -> None:
        if isinstance(value, str) and len(value) > self.max_length:
            raise ValidationError(
                _(f'Content exceeds maximum length of {self.max_length} characters.'),
                code='content_too_long'
            )


class AlphanumericValidator:
    """
    Validates that input contains only alphanumeric characters and optionally spaces.
    """

    def __init__(self, allow_spaces: bool = False):
        self.allow_spaces = allow_spaces
        pattern = r'^[a-zA-Z0-9\s]+$' if allow_spaces else r'^[a-zA-Z0-9]+$'
        self.pattern = re.compile(pattern)

    def __call__(self, value: str) -> None:
        if not self.pattern.match(value):
            spaces_msg = ' and spaces' if self.allow_spaces else ''
            raise ValidationError(
                _(f'Only alphanumeric characters{spaces_msg} are allowed.'),
                code='invalid_characters'
            )
