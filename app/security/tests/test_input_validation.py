"""
Unit tests for Input Validation
"""

import pytest
from django.core.exceptions import ValidationError
from app.security.validation.input_validators import (
    InputValidator,
    validate_input,
    is_safe_string,
)


class TestInputValidator:
    """Test InputValidator class methods"""

    def test_validate_email_valid(self):
        """Test valid email validation"""
        result = InputValidator.validate_email("test@example.com")
        assert result == "test@example.com"

    def test_validate_email_invalid(self):
        """Test invalid email validation"""
        with pytest.raises(ValueError, match="Invalid email"):
            InputValidator.validate_email("not-an-email")

    def test_validate_integer_valid(self):
        """Test valid integer validation"""
        result = InputValidator.validate_integer("25", min_val=18, max_val=120)
        assert result == 25

    def test_validate_integer_below_minimum(self):
        """Test integer below minimum"""
        with pytest.raises(ValueError, match="below minimum"):
            InputValidator.validate_integer("15", min_val=18, max_val=120)

    def test_validate_integer_above_maximum(self):
        """Test integer above maximum"""
        with pytest.raises(ValueError, match="above maximum"):
            InputValidator.validate_integer("150", min_val=18, max_val=120)

    def test_validate_integer_invalid(self):
        """Test invalid integer"""
        with pytest.raises(ValueError, match="Invalid integer"):
            InputValidator.validate_integer("not-a-number")

    def test_validate_string_sql_injection(self):
        """Test SQL injection detection in strings"""
        with pytest.raises(ValueError, match="SQL injection"):
            InputValidator.validate_string("'; DROP TABLE users; --")

    def test_validate_string_xss(self):
        """Test XSS detection in strings"""
        with pytest.raises(ValueError, match="XSS attack"):
            InputValidator.validate_string("<script>alert('xss')</script>")

    def test_validate_string_safe(self):
        """Test safe string validation"""
        result = InputValidator.validate_string("Hello World", safe_only=True)
        assert result == "Hello World"

    def test_validate_string_length_constraints(self):
        """Test string length validation"""
        with pytest.raises(ValueError, match="too short"):
            InputValidator.validate_string("ab", min_length=5)

        with pytest.raises(ValueError, match="too long"):
            InputValidator.validate_string("x" * 100, max_length=50)

    def test_validate_choice_valid(self):
        """Test valid choice validation"""
        result = InputValidator.validate_choice("admin", ["user", "admin", "guest"])
        assert result == "admin"

    def test_validate_choice_invalid(self):
        """Test invalid choice validation"""
        with pytest.raises(ValueError, match="Invalid choice"):
            InputValidator.validate_choice("superuser", ["user", "admin"])


class TestValidateInput:
    """Test validate_input function with schemas"""

    def test_validate_input_all_required_fields_present(self):
        """Test validation when all required fields are present"""
        data = {"email": "test@example.com", "age": 25}
        schema = {
            "email": "email",
            "age": ("integer", {"min": 18, "max": 120}),
        }

        result = validate_input(data, schema)
        assert result["email"] == "test@example.com"
        assert result["age"] == 25

    def test_validate_input_missing_required_field(self):
        """Test validation when required field is missing"""
        data = {"email": "test@example.com"}
        schema = {
            "email": "email",
            "age": ("integer", {"min": 18, "max": 120}),
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_input(data, schema)

        assert "age" in exc_info.value.message_dict
        assert "required" in str(exc_info.value.message_dict["age"][0]).lower()

    def test_validate_input_optional_field(self):
        """Test validation with optional field"""
        data = {"email": "test@example.com"}
        schema = {
            "email": "email",
            "age": ("integer", {"min": 18, "max": 120, "required": False}),
        }

        result = validate_input(data, schema)
        assert result["email"] == "test@example.com"
        assert "age" not in result

    def test_validate_input_invalid_range(self):
        """Test validation with invalid range"""
        data = {"email": "test@example.com", "age": 15}
        schema = {
            "email": "email",
            "age": ("integer", {"min": 18, "max": 120}),
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_input(data, schema)

        assert "age" in exc_info.value.message_dict

    def test_validate_input_using_min_max_params(self):
        """Test that both 'min'/'max' and 'min_val'/'max_val' work"""
        data1 = {"age": 25}
        schema1 = {"age": ("integer", {"min": 18, "max": 120})}
        result1 = validate_input(data1, schema1)
        assert result1["age"] == 25

        data2 = {"age": 25}
        schema2 = {"age": ("integer", {"min_val": 18, "max_val": 120})}
        result2 = validate_input(data2, schema2)
        assert result2["age"] == 25

    def test_validate_input_multiple_fields(self):
        """Test validation with multiple fields"""
        data = {
            "email": "test@example.com",
            "age": 25,
            "name": "John Doe",
            "role": "admin",
        }
        schema = {
            "email": "email",
            "age": ("integer", {"min": 18, "max": 120}),
            "name": ("string", {"min_length": 1, "max_length": 100}),
            "role": ("choice", {"choices": ["user", "admin", "guest"]}),
        }

        result = validate_input(data, schema)
        assert len(result) == 4
        assert result["email"] == "test@example.com"
        assert result["age"] == 25
        assert result["name"] == "John Doe"
        assert result["role"] == "admin"

    def test_validate_input_require_all_false(self):
        """Test validation with require_all=False"""
        data = {"email": "test@example.com"}
        schema = {
            "email": "email",
            "age": ("integer", {"min": 18, "max": 120}),
        }

        result = validate_input(data, schema, require_all=False)
        assert result["email"] == "test@example.com"
        assert "age" not in result


class TestIsSafeString:
    """Test is_safe_string helper function"""

    def test_safe_string(self):
        """Test that safe strings pass"""
        assert is_safe_string("Hello World 123") is True

    def test_sql_injection_string(self):
        """Test that SQL injection strings fail"""
        assert is_safe_string("'; DROP TABLE users; --") is False

    def test_xss_string(self):
        """Test that XSS strings fail"""
        assert is_safe_string("<script>alert('xss')</script>") is False


class TestSQLInjectionPatterns:
    """Test various SQL injection patterns"""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "'; DROP TABLE users; --",  # Detects: DROP TABLE and ; --
            "' UNION SELECT * FROM users WHERE 1=1--",  # Detects: UNION SELECT and SELECT FROM WHERE
            "; DELETE FROM users WHERE '1'='1",  # Detects: DELETE FROM
        ],
    )
    def test_sql_injection_detection(self, malicious_input):
        """Test that various SQL injection patterns are detected"""
        with pytest.raises(ValueError, match="SQL injection"):
            InputValidator.validate_string(malicious_input)


class TestXSSPatterns:
    """Test various XSS patterns"""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='http://evil.com'></iframe>",
            "javascript:alert('xss')",
            "<body onload=alert('xss')>",
            "<svg onload=alert('xss')>",
        ],
    )
    def test_xss_detection(self, malicious_input):
        """Test that various XSS patterns are detected"""
        with pytest.raises(ValueError, match="XSS attack"):
            InputValidator.validate_string(malicious_input)
