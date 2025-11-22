"""
Secure serializers with built-in validation and sanitization.

This module provides DRF serializers that automatically apply:
- Input validation
- Input sanitization
- Security checks
"""

from typing import Any, Dict, List, Optional

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .sanitizers import InputSanitizer
from .validators import (
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

User = get_user_model()


class SecureSerializerMixin:
    """
    Mixin that adds automatic sanitization to serializers.

    Usage:
        class MySerializer(SecureSerializerMixin, serializers.Serializer):
            sanitize_fields = ['name', 'description']
            email_fields = ['email', 'contact_email']
    """

    # Fields to sanitize (removes HTML tags by default)
    sanitize_fields: List[str] = []

    # Fields that contain emails (special sanitization)
    email_fields: List[str] = []

    # Fields that contain URLs (special sanitization)
    url_fields: List[str] = []

    # Fields that contain usernames (special sanitization)
    username_fields: List[str] = []

    # Fields that contain phone numbers (special sanitization)
    phone_fields: List[str] = []

    def to_internal_value(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Override to sanitize data before validation."""
        # Call parent's to_internal_value first
        data = super().to_internal_value(data)  # type: ignore

        # Sanitize fields
        sanitizer = InputSanitizer()

        # Sanitize HTML fields
        for field_name in getattr(self, 'sanitize_fields', []):
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = sanitizer.sanitize_html(data[field_name])

        # Sanitize email fields
        for field_name in getattr(self, 'email_fields', []):
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = sanitizer.sanitize_email(data[field_name])

        # Sanitize URL fields
        for field_name in getattr(self, 'url_fields', []):
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = sanitizer.sanitize_url(data[field_name])

        # Sanitize username fields
        for field_name in getattr(self, 'username_fields', []):
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = sanitizer.sanitize_username(data[field_name])

        # Sanitize phone fields
        for field_name in getattr(self, 'phone_fields', []):
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = sanitizer.sanitize_phone(data[field_name])

        return data


class SecureCharField(serializers.CharField):
    """
    CharField with built-in XSS and injection prevention.
    """

    def __init__(self, *args, **kwargs):
        # Add security validators
        validators = kwargs.pop('validators', [])
        validators.extend([
            NoXSSValidator(),
            NoSQLInjectionValidator(),
            NoCommandInjectionValidator(),
        ])
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_html(data)

        return super().to_internal_value(data)


class SecureEmailField(serializers.EmailField):
    """
    EmailField with enhanced validation and sanitization.
    """

    def __init__(self, *args, **kwargs):
        # Add strict email validator
        validators = kwargs.pop('validators', [])
        validators.append(StrictEmailValidator())
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_email(data)

        return super().to_internal_value(data)


class SecureURLField(serializers.URLField):
    """
    URLField with SSRF prevention and sanitization.
    """

    def __init__(self, *args, **kwargs):
        # Add safe URL validator
        validators = kwargs.pop('validators', [])
        validators.append(SafeURLValidator())
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_url(data)

        return super().to_internal_value(data)


class UsernameField(serializers.CharField):
    """
    Username field with strict validation.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('min_length', 3)
        kwargs.setdefault('max_length', 30)

        # Add username validator
        validators = kwargs.pop('validators', [])
        validators.append(UsernameValidator())
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_username(data)

        return super().to_internal_value(data)


class PhoneNumberField(serializers.CharField):
    """
    Phone number field with international format validation.
    """

    def __init__(self, *args, **kwargs):
        # Add phone validator
        validators = kwargs.pop('validators', [])
        validators.append(PhoneNumberValidator())
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_phone(data)

        return super().to_internal_value(data)


class SecureFilePathField(serializers.CharField):
    """
    File path field with path traversal prevention.
    """

    def __init__(self, *args, **kwargs):
        # Add path traversal validator
        validators = kwargs.pop('validators', [])
        validators.append(NoPathTraversalValidator())
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_path(data)

        return super().to_internal_value(data)


class AlphanumericField(serializers.CharField):
    """
    Field that only accepts alphanumeric characters.
    """

    def __init__(self, allow_spaces: bool = False, *args, **kwargs):
        self.allow_spaces = allow_spaces

        # Add alphanumeric validator
        validators = kwargs.pop('validators', [])
        validators.append(AlphanumericValidator(allow_spaces=allow_spaces))
        kwargs['validators'] = validators

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data: Any) -> str:
        # Sanitize before validation
        if isinstance(data, str):
            data = InputSanitizer.sanitize_alphanumeric(data, allow_spaces=self.allow_spaces)

        return super().to_internal_value(data)


# =============================================================================
# Example Serializers
# =============================================================================


class UserRegistrationSerializer(SecureSerializerMixin, serializers.Serializer):
    """
    Secure user registration serializer.
    """

    username_fields = ['username']
    email_fields = ['email']
    sanitize_fields = ['first_name', 'last_name']

    username = UsernameField()
    email = SecureEmailField()
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    first_name = SecureCharField(
        max_length=150,
        required=False,
        allow_blank=True,
        validators=[ContentLengthValidator(max_length=150)]
    )
    last_name = SecureCharField(
        max_length=150,
        required=False,
        allow_blank=True,
        validators=[ContentLengthValidator(max_length=150)]
    )

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })

        # Remove password_confirm from validated data
        attrs.pop('password_confirm')

        return attrs

    def validate_username(self, value: str) -> str:
        """Validate that username is unique."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError('Username already exists.')
        return value

    def validate_email(self, value: str) -> str:
        """Validate that email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists.')
        return value


class UserLoginSerializer(SecureSerializerMixin, serializers.Serializer):
    """
    Secure user login serializer.
    """

    username_fields = ['username']

    username = UsernameField()
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )


class PasswordChangeSerializer(serializers.Serializer):
    """
    Secure password change serializer.
    """

    old_password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that new passwords match."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Passwords do not match.'
            })

        # Remove password_confirm from validated data
        attrs.pop('new_password_confirm')

        return attrs


class UserProfileSerializer(SecureSerializerMixin, serializers.Serializer):
    """
    Secure user profile serializer.
    """

    email_fields = ['email']
    sanitize_fields = ['first_name', 'last_name', 'bio']
    phone_fields = ['phone']

    first_name = SecureCharField(
        max_length=150,
        required=False,
        allow_blank=True,
        validators=[ContentLengthValidator(max_length=150)]
    )
    last_name = SecureCharField(
        max_length=150,
        required=False,
        allow_blank=True,
        validators=[ContentLengthValidator(max_length=150)]
    )
    email = SecureEmailField(required=False)
    phone = PhoneNumberField(required=False, allow_blank=True)
    bio = SecureCharField(
        max_length=500,
        required=False,
        allow_blank=True,
        validators=[ContentLengthValidator(max_length=500)]
    )


class CommentSerializer(SecureSerializerMixin, serializers.Serializer):
    """
    Example serializer for user-generated content with strict validation.
    """

    sanitize_fields = ['content', 'title']

    title = SecureCharField(
        max_length=200,
        validators=[ContentLengthValidator(max_length=200)]
    )
    content = SecureCharField(
        max_length=5000,
        validators=[ContentLengthValidator(max_length=5000)]
    )
    author_name = SecureCharField(
        max_length=100,
        validators=[ContentLengthValidator(max_length=100)]
    )
