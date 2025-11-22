"""
Tests for sanitizers.
"""

from django.test import TestCase

from input_validation.sanitizers import DictSanitizer, InputSanitizer, sanitize_request_data


class InputSanitizerTests(TestCase):
    """Tests for InputSanitizer."""

    def setUp(self):
        self.sanitizer = InputSanitizer()

    def test_sanitize_html_strip_tags(self):
        """HTML tags should be stripped when strip_tags=True."""
        input_text = '<script>alert("XSS")</script>Hello<b>World</b>'
        expected = 'alert("XSS")HelloWorld'  # Content inside tags remains
        result = self.sanitizer.sanitize_html(input_text, strip_tags=True)
        self.assertEqual(result, expected)

    def test_sanitize_html_escape_tags(self):
        """HTML tags should be escaped when strip_tags=False."""
        input_text = '<script>alert("XSS")</script>'
        result = self.sanitizer.sanitize_html(input_text, strip_tags=False)
        self.assertIn('&lt;script&gt;', result)
        self.assertIn('&lt;/script&gt;', result)

    def test_sanitize_html_remove_null_bytes(self):
        """Null bytes should be removed."""
        input_text = 'Hello\x00World'
        expected = 'HelloWorld'
        result = self.sanitizer.sanitize_html(input_text)
        self.assertEqual(result, expected)

    def test_sanitize_sql(self):
        """SQL injection attempts should be sanitized."""
        input_text = "admin'--"
        result = self.sanitizer.sanitize_sql(input_text)
        self.assertNotIn('--', result)
        self.assertIn("''", result)  # Single quotes should be doubled

    def test_sanitize_path(self):
        """Path traversal attempts should be sanitized."""
        test_cases = [
            ('../../../etc/passwd', 'etc/passwd'),
            ('~/secrets', 'secrets'),
            ('/absolute/path', 'absolute/path'),
            ('path\\to\\file', 'path/to/file'),
        ]

        for input_path, expected in test_cases:
            with self.subTest(input_path=input_path):
                result = self.sanitizer.sanitize_path(input_path)
                self.assertEqual(result, expected)

    def test_sanitize_shell(self):
        """Shell metacharacters should be removed."""
        input_text = 'file.txt; rm -rf /'
        result = self.sanitizer.sanitize_shell(input_text)
        self.assertNotIn(';', result)
        self.assertNotIn('|', result)
        self.assertNotIn('&', result)

    def test_sanitize_email(self):
        """Emails should be sanitized."""
        test_cases = [
            ('  User@Example.COM  ', 'user@example.com'),
            ('user@example.com\nBCC:evil@evil.com', 'user@example.combcc:evil@evil.com'),
            ('user@example.com%0a', 'user@example.com'),
        ]

        for input_email, expected in test_cases:
            with self.subTest(input_email=input_email):
                result = self.sanitizer.sanitize_email(input_email)
                self.assertEqual(result, expected)

    def test_sanitize_url(self):
        """URLs should be sanitized."""
        input_url = '  https://example.com  '
        result = self.sanitizer.sanitize_url(input_url)
        self.assertEqual(result.strip(), result)
        self.assertNotIn(' ', result)

    def test_sanitize_username(self):
        """Usernames should be sanitized."""
        test_cases = [
            ('  User123  ', 'user123'),
            ('User@Name!', 'username'),
            ('Test_User-123', 'test_user-123'),
        ]

        for input_username, expected in test_cases:
            with self.subTest(input_username=input_username):
                result = self.sanitizer.sanitize_username(input_username)
                self.assertEqual(result, expected)

    def test_sanitize_phone(self):
        """Phone numbers should be sanitized."""
        test_cases = [
            ('+1 (234) 567-890', '+1234567890'),
            ('  +44 7911 123456  ', '+447911123456'),
            ('+1-234-567-890', '+1234567890'),
        ]

        for input_phone, expected in test_cases:
            with self.subTest(input_phone=input_phone):
                result = self.sanitizer.sanitize_phone(input_phone)
                self.assertEqual(result, expected)

    def test_sanitize_integer_valid(self):
        """Valid integers should be parsed."""
        test_cases = [
            ('123', 123),
            (456, 456),
            ('0', 0),
        ]

        for input_value, expected in test_cases:
            with self.subTest(input_value=input_value):
                result = self.sanitizer.sanitize_integer(input_value)
                self.assertEqual(result, expected)

    def test_sanitize_integer_with_bounds(self):
        """Integers should respect min/max bounds."""
        # Within bounds
        result = self.sanitizer.sanitize_integer(50, min_value=0, max_value=100)
        self.assertEqual(result, 50)

        # Below min
        result = self.sanitizer.sanitize_integer(-10, min_value=0)
        self.assertIsNone(result)

        # Above max
        result = self.sanitizer.sanitize_integer(200, max_value=100)
        self.assertIsNone(result)

    def test_sanitize_integer_invalid(self):
        """Invalid integers should return None."""
        invalid_inputs = ['abc', 'not a number', None]

        for input_value in invalid_inputs:
            with self.subTest(input_value=input_value):
                result = self.sanitizer.sanitize_integer(input_value)
                self.assertIsNone(result)

    def test_sanitize_alphanumeric_no_spaces(self):
        """Alphanumeric sanitization without spaces."""
        input_text = 'Hello World! 123'
        expected = 'HelloWorld123'
        result = self.sanitizer.sanitize_alphanumeric(input_text, allow_spaces=False)
        self.assertEqual(result, expected)

    def test_sanitize_alphanumeric_with_spaces(self):
        """Alphanumeric sanitization with spaces."""
        input_text = 'Hello World! 123'
        expected = 'Hello World 123'
        result = self.sanitizer.sanitize_alphanumeric(input_text, allow_spaces=True)
        self.assertEqual(result, expected)

    def test_truncate(self):
        """Text should be truncated to max length."""
        # Text within limit
        result = self.sanitizer.truncate('Hello', max_length=10)
        self.assertEqual(result, 'Hello')

        # Text exceeding limit
        result = self.sanitizer.truncate('Hello World', max_length=8)
        self.assertEqual(result, 'Hello...')

        # Custom suffix
        result = self.sanitizer.truncate('Hello World', max_length=8, suffix='~')
        self.assertEqual(result, 'Hello W~')


class DictSanitizerTests(TestCase):
    """Tests for DictSanitizer."""

    def test_sanitize_html_fields(self):
        """HTML fields should be sanitized."""
        sanitizer = DictSanitizer(html_fields=['description'])

        data = {
            'title': 'Test',
            'description': '<script>alert("XSS")</script>Hello',
        }

        result = sanitizer.sanitize(data)
        self.assertNotIn('<script>', result['description'])
        self.assertIn('Hello', result['description'])

    def test_sanitize_email_fields(self):
        """Email fields should be sanitized."""
        sanitizer = DictSanitizer(email_fields=['email'])

        data = {
            'name': 'John',
            'email': '  User@Example.COM  ',
        }

        result = sanitizer.sanitize(data)
        self.assertEqual(result['email'], 'user@example.com')

    def test_sanitize_url_fields(self):
        """URL fields should be sanitized."""
        sanitizer = DictSanitizer(url_fields=['website'])

        data = {
            'name': 'Company',
            'website': '  https://example.com  ',
        }

        result = sanitizer.sanitize(data)
        self.assertNotIn(' ', result['website'])

    def test_sanitize_nested_dicts(self):
        """Nested dictionaries should be sanitized."""
        sanitizer = DictSanitizer(html_fields=['content'])

        data = {
            'post': {
                'title': 'Test',
                'content': '<script>alert("XSS")</script>Hello',
            }
        }

        result = sanitizer.sanitize(data)
        self.assertNotIn('<script>', result['post']['content'])

    def test_sanitize_lists(self):
        """Lists should be sanitized."""
        sanitizer = DictSanitizer(html_fields=['comment'])

        data = {
            'comments': [
                {'comment': '<script>XSS</script>Comment 1'},
                {'comment': '<b>Comment 2</b>'},
            ]
        }

        result = sanitizer.sanitize(data)
        self.assertNotIn('<script>', result['comments'][0]['comment'])
        self.assertNotIn('<b>', result['comments'][1]['comment'])


class SanitizeRequestDataTests(TestCase):
    """Tests for sanitize_request_data convenience function."""

    def test_sanitize_dict(self):
        """Dictionary data should be sanitized."""
        data = {
            'email': '  User@Example.COM  ',
            'description': '<script>XSS</script>Text',
        }

        result = sanitize_request_data(
            data,
            email_fields=['email'],
            html_fields=['description']
        )

        self.assertEqual(result['email'], 'user@example.com')
        self.assertNotIn('<script>', result['description'])

    def test_sanitize_list(self):
        """List data should be sanitized."""
        data = [
            {'email': '  User1@Example.COM  '},
            {'email': '  User2@Example.COM  '},
        ]

        result = sanitize_request_data(data, email_fields=['email'])

        self.assertEqual(result[0]['email'], 'user1@example.com')
        self.assertEqual(result[1]['email'], 'user2@example.com')

    def test_sanitize_mixed_data(self):
        """Mixed data types should be handled."""
        data = {
            'users': [
                {'email': '  User1@Example.COM  '},
                {'email': '  User2@Example.COM  '},
            ],
            'admin_email': '  Admin@Example.COM  ',
        }

        result = sanitize_request_data(data, email_fields=['email', 'admin_email'])

        self.assertEqual(result['admin_email'], 'admin@example.com')
        self.assertEqual(result['users'][0]['email'], 'user1@example.com')
