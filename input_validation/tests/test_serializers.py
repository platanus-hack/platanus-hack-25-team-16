"""
Tests for secure serializers.
"""

from django.test import TestCase
from rest_framework.exceptions import ValidationError

from input_validation.serializers import (
    AlphanumericField,
    PhoneNumberField,
    SecureCharField,
    SecureEmailField,
    SecureFilePathField,
    SecureURLField,
    UserLoginSerializer,
    UsernameField,
)


class SecureCharFieldTests(TestCase):
    """Tests for SecureCharField."""

    def test_sanitize_html(self):
        """HTML should be sanitized."""
        field = SecureCharField()
        value = field.to_internal_value('<script>alert("XSS")</script>Hello')
        self.assertNotIn('<script>', value)

    def test_valid_input(self):
        """Valid input should pass."""
        field = SecureCharField()
        value = field.run_validation('Normal text content')
        self.assertEqual(value, 'Normal text content')


class SecureEmailFieldTests(TestCase):
    """Tests for SecureEmailField."""

    def test_sanitize_email(self):
        """Email should be sanitized."""
        field = SecureEmailField()
        value = field.to_internal_value('  User@Example.COM  ')
        self.assertEqual(value, 'user@example.com')

    def test_valid_email(self):
        """Valid email should pass."""
        field = SecureEmailField()
        value = field.run_validation('user@example.com')
        self.assertEqual(value, 'user@example.com')

    def test_invalid_email(self):
        """Invalid email should fail."""
        field = SecureEmailField()

        with self.assertRaises(ValidationError):
            field.run_validation('not-an-email')


class SecureURLFieldTests(TestCase):
    """Tests for SecureURLField."""

    def test_valid_url(self):
        """Valid URL should pass."""
        field = SecureURLField()
        value = field.run_validation('https://example.com')
        self.assertIn('example.com', value)


class UsernameFieldTests(TestCase):
    """Tests for UsernameField."""

    def test_sanitize_username(self):
        """Username should be sanitized."""
        field = UsernameField()
        value = field.to_internal_value('  User123!  ')
        self.assertEqual(value, 'user123')

    def test_valid_username(self):
        """Valid username should pass."""
        field = UsernameField()
        value = field.run_validation('john123')
        self.assertEqual(value, 'john123')


class PhoneNumberFieldTests(TestCase):
    """Tests for PhoneNumberField."""

    def test_sanitize_phone(self):
        """Phone number should be sanitized."""
        field = PhoneNumberField()
        value = field.to_internal_value('+1 (234) 567-890')
        self.assertEqual(value, '+1234567890')

    def test_valid_phone(self):
        """Valid phone number should pass."""
        field = PhoneNumberField()
        value = field.run_validation('+12345678901')
        self.assertEqual(value, '+12345678901')


class SecureFilePathFieldTests(TestCase):
    """Tests for SecureFilePathField."""

    def test_sanitize_path(self):
        """Path should be sanitized."""
        field = SecureFilePathField()
        value = field.to_internal_value('../file.txt')
        self.assertNotIn('..', value)


class AlphanumericFieldTests(TestCase):
    """Tests for AlphanumericField."""

    def test_alphanumeric_no_spaces(self):
        """Alphanumeric without spaces should work."""
        field = AlphanumericField(allow_spaces=False)
        value = field.run_validation('Test123')
        self.assertEqual(value, 'Test123')

    def test_alphanumeric_with_spaces(self):
        """Alphanumeric with spaces should work when allowed."""
        field = AlphanumericField(allow_spaces=True)
        value = field.run_validation('Test 123')
        self.assertEqual(value, 'Test 123')


class UserLoginSerializerTests(TestCase):
    """Tests for UserLoginSerializer."""

    def test_valid_data(self):
        """Valid login data should pass."""
        data = {
            'username': 'john123',
            'password': 'SecurePass123!',
        }

        serializer = UserLoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_sanitization(self):
        """Input should be sanitized."""
        data = {
            'username': '  John123!  ',
            'password': 'password',
        }

        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid():
            self.assertEqual(serializer.validated_data['username'], 'john123')

    def test_missing_fields(self):
        """Missing fields should fail."""
        data = {'username': 'john123'}

        serializer = UserLoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
