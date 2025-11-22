"""
Input Validation Module

Provides comprehensive input validation to prevent injection attacks.
"""

import re
import json
from typing import Any, Dict, List, Union, Optional
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator, URLValidator
from rest_framework import serializers


class InputValidator:
    """
    Main input validator class with various validation methods.
    """

    # Email validator
    email_validator = EmailValidator()

    # URL validator
    url_validator = URLValidator()

    # Phone regex patterns
    PHONE_PATTERNS = {
        "international": re.compile(r"^\+?1?\d{9,15}$"),
        "us": re.compile(r"^(\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$"),
        "uk": re.compile(r"^(\+44)?[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}$"),
    }

    # UUID pattern
    UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    # Alphanumeric with limited special chars
    SAFE_STRING_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-_.,!?@#$%&*()+=/\\;:\'"]*$')

    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
        re.compile(r"(\bselect\b.*\bfrom\b)", re.IGNORECASE),
        re.compile(r"(\binsert\b.*\binto\b)", re.IGNORECASE),
        re.compile(r"(\bdelete\b.*\bfrom\b)", re.IGNORECASE),
        re.compile(r"(\bdrop\b.*\btable\b)", re.IGNORECASE),
        re.compile(r"(\bupdate\b.*\bset\b)", re.IGNORECASE),
        re.compile(r"('\s*or\s*')", re.IGNORECASE),
        re.compile(r"(;\s*--)", re.IGNORECASE),
    ]

    # XSS patterns
    XSS_PATTERNS = [
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    ]

    @classmethod
    def validate_email(cls, value: str) -> str:
        """Validate email address."""
        value = value.strip().lower()
        try:
            cls.email_validator(value)
        except ValidationError:
            raise ValueError(f"Invalid email address: {value}")
        return value

    @classmethod
    def validate_url(cls, value: str) -> str:
        """Validate URL."""
        value = value.strip()
        try:
            cls.url_validator(value)
        except ValidationError:
            raise ValueError(f"Invalid URL: {value}")
        return value

    @classmethod
    def validate_phone(cls, value: str, format: str = "international") -> str:
        """Validate phone number."""
        value = re.sub(r"[^\d+\-.\s()]", "", value)
        pattern = cls.PHONE_PATTERNS.get(format, cls.PHONE_PATTERNS["international"])

        if not pattern.match(value):
            raise ValueError(f"Invalid phone number: {value}")

        return value

    @classmethod
    def validate_uuid(cls, value: str) -> str:
        """Validate UUID."""
        value = value.strip().lower()
        if not cls.UUID_PATTERN.match(value):
            raise ValueError(f"Invalid UUID: {value}")
        return value

    @classmethod
    def validate_integer(
        cls, value: Any, min_val: Optional[int] = None, max_val: Optional[int] = None
    ) -> int:
        """Validate integer with optional range."""
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid integer: {value}")

        if min_val is not None and int_value < min_val:
            raise ValueError(f"Value {int_value} is below minimum {min_val}")

        if max_val is not None and int_value > max_val:
            raise ValueError(f"Value {int_value} is above maximum {max_val}")

        return int_value

    @classmethod
    def validate_float(
        cls,
        value: Any,
        min_val: Optional[float] = None,
        max_val: Optional[float] = None,
    ) -> float:
        """Validate float with optional range."""
        try:
            float_value = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid float: {value}")

        if min_val is not None and float_value < min_val:
            raise ValueError(f"Value {float_value} is below minimum {min_val}")

        if max_val is not None and float_value > max_val:
            raise ValueError(f"Value {float_value} is above maximum {max_val}")

        return float_value

    @classmethod
    def validate_choice(cls, value: Any, choices: List[Any]) -> Any:
        """Validate value is in allowed choices."""
        if value not in choices:
            raise ValueError(f"Invalid choice: {value}. Must be one of {choices}")
        return value

    @classmethod
    def validate_string(
        cls,
        value: str,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        safe_only: bool = False,
    ) -> str:
        """Validate string with various constraints."""
        if not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value)}")

        value = value.strip()

        # Check length
        if min_length is not None and len(value) < min_length:
            raise ValueError(f"String too short: minimum {min_length} characters")

        if max_length is not None and len(value) > max_length:
            raise ValueError(f"String too long: maximum {max_length} characters")

        # Check pattern
        if pattern:
            if not re.match(pattern, value):
                raise ValueError("String does not match required pattern")

        # Check for safe characters only
        if safe_only and not cls.SAFE_STRING_PATTERN.match(value):
            raise ValueError("String contains unsafe characters")

        # Check for SQL injection
        for sql_pattern in cls.SQL_INJECTION_PATTERNS:
            if sql_pattern.search(value):
                raise ValueError("Potential SQL injection detected")

        # Check for XSS
        for xss_pattern in cls.XSS_PATTERNS:
            if xss_pattern.search(value):
                raise ValueError("Potential XSS attack detected")

        return value

    @classmethod
    def validate_json(cls, value: Union[str, dict]) -> dict:
        """Validate JSON string or dict."""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {e}")

        if not isinstance(value, dict):
            raise ValueError("Expected JSON object (dict)")

        return value

    @classmethod
    def validate_list(cls, value: Union[str, list], item_validator=None) -> list:
        """Validate list with optional item validation."""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                # Try comma-separated
                value = [v.strip() for v in value.split(",")]

        if not isinstance(value, list):
            raise ValueError("Expected list")

        # Validate individual items if validator provided
        if item_validator:
            validated_items = []
            for item in value:
                try:
                    validated_items.append(item_validator(item))
                except Exception as e:
                    raise ValueError(f"Invalid list item: {e}")
            return validated_items

        return value


def validate_input(
    data: Dict[str, Any], schema: Dict[str, Any], require_all: bool = True
) -> Dict[str, Any]:
    """
    Validate input data against a schema.

    Args:
        data: Input data dictionary
        schema: Validation schema
        require_all: If True, all schema fields are required (default: True)

    Returns:
        Validated and sanitized data

    Example schema:
        {
            'email': 'email',
            'age': ('integer', {'min': 0, 'max': 120}),  # or use min_val/max_val
            'phone': ('phone', {'format': 'us'}),
            'role': ('choice', {'choices': ['user', 'admin']}),
            'name': ('string', {'min_length': 1, 'max_length': 100}),
        }

    For optional fields, use a tuple with 'required' option:
        {
            'email': 'email',  # Required by default
            'phone': ('phone', {'format': 'us', 'required': False}),  # Optional
        }
    """
    validator = InputValidator()
    validated = {}

    for field, rules in schema.items():
        # Parse rules to check if field is optional
        if isinstance(rules, str):
            validator_name = rules
            options = {}
        elif isinstance(rules, tuple):
            validator_name = rules[0]
            options = rules[1] if len(rules) > 1 else {}
        else:
            raise ValueError(f"Invalid schema for field {field}")

        # Check if field is required
        field_required = options.get("required", require_all)

        # Handle missing fields
        if field not in data:
            if field_required:
                raise ValidationError({field: "This field is required"})
            else:
                continue

        value = data[field]

        # Remove 'required' from options before passing to validators
        validator_options = {k: v for k, v in options.items() if k != "required"}

        # Apply validation
        try:
            if validator_name == "email":
                validated[field] = validator.validate_email(value)
            elif validator_name == "url":
                validated[field] = validator.validate_url(value)
            elif validator_name == "phone":
                validated[field] = validator.validate_phone(value, **validator_options)
            elif validator_name == "uuid":
                validated[field] = validator.validate_uuid(value)
            elif validator_name == "integer" or validator_name == "int":
                # Map 'min'/'max' to 'min_val'/'max_val' for consistency
                int_options = {}
                if "min" in validator_options:
                    int_options["min_val"] = validator_options["min"]
                if "max" in validator_options:
                    int_options["max_val"] = validator_options["max"]
                if "min_val" in validator_options:
                    int_options["min_val"] = validator_options["min_val"]
                if "max_val" in validator_options:
                    int_options["max_val"] = validator_options["max_val"]
                validated[field] = validator.validate_integer(value, **int_options)
            elif validator_name == "float":
                # Map 'min'/'max' to 'min_val'/'max_val' for consistency
                float_options = {}
                if "min" in validator_options:
                    float_options["min_val"] = validator_options["min"]
                if "max" in validator_options:
                    float_options["max_val"] = validator_options["max"]
                if "min_val" in validator_options:
                    float_options["min_val"] = validator_options["min_val"]
                if "max_val" in validator_options:
                    float_options["max_val"] = validator_options["max_val"]
                validated[field] = validator.validate_float(value, **float_options)
            elif validator_name == "choice":
                validated[field] = validator.validate_choice(value, **validator_options)
            elif validator_name == "string" or validator_name == "str":
                validated[field] = validator.validate_string(value, **validator_options)
            elif validator_name == "json":
                validated[field] = validator.validate_json(value)
            elif validator_name == "list":
                validated[field] = validator.validate_list(value, **validator_options)
            else:
                # Default to string validation
                validated[field] = validator.validate_string(value, safe_only=True)
        except Exception as e:
            raise ValidationError({field: str(e)})

    return validated


class SecureSerializer(serializers.Serializer):
    """
    Base serializer with built-in security validation.
    """

    def validate(self, attrs):
        """Add security validation to all fields."""
        validator = InputValidator()

        for field_name, value in attrs.items():
            if isinstance(value, str):
                # Check for SQL injection and XSS in string fields
                try:
                    validator.validate_string(value, safe_only=False)
                except ValueError as e:
                    raise serializers.ValidationError({field_name: str(e)})

        return attrs


class SecureModelSerializer(serializers.ModelSerializer):
    """
    Model serializer with built-in security validation.
    """

    def validate(self, attrs):
        """Add security validation to all fields."""
        validator = InputValidator()

        for field_name, value in attrs.items():
            if isinstance(value, str):
                # Check for SQL injection and XSS in string fields
                try:
                    validator.validate_string(value, safe_only=False)
                except ValueError as e:
                    raise serializers.ValidationError({field_name: str(e)})

        return attrs


# Convenience functions
def is_safe_string(value: str) -> bool:
    """Check if a string is safe (no injection patterns)."""
    try:
        InputValidator.validate_string(value, safe_only=True)
        return True
    except ValueError:
        return False


def clean_input(value: str) -> str:
    """Clean input string by removing potentially dangerous characters."""
    # Remove HTML tags
    value = re.sub(r"<[^>]+>", "", value)

    # Remove JavaScript
    value = re.sub(r"javascript:", "", value, flags=re.IGNORECASE)

    # Remove SQL keywords
    sql_keywords = ["union", "select", "insert", "update", "delete", "drop"]
    for keyword in sql_keywords:
        value = re.sub(rf"\b{keyword}\b", "", value, flags=re.IGNORECASE)

    return value.strip()
