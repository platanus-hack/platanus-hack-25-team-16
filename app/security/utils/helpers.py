"""
Security Helper Functions

Utility functions for security-related tasks.
"""

import hashlib
import hmac
import secrets
import string
from typing import Any, Optional
from django.conf import settings
from django.utils.crypto import constant_time_compare, get_random_string


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Token length

    Returns:
        Secure random token
    """
    return secrets.token_urlsafe(length)


def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
) -> str:
    """
    Generate a secure random password.

    Args:
        length: Password length
        include_uppercase: Include uppercase letters
        include_lowercase: Include lowercase letters
        include_digits: Include digits
        include_symbols: Include special characters

    Returns:
        Secure random password
    """
    chars = ""
    if include_lowercase:
        chars += string.ascii_lowercase
    if include_uppercase:
        chars += string.ascii_uppercase
    if include_digits:
        chars += string.digits
    if include_symbols:
        chars += string.punctuation

    if not chars:
        chars = string.ascii_letters + string.digits

    # Ensure password has at least one of each required type
    password = []
    if include_lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if include_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if include_digits:
        password.append(secrets.choice(string.digits))
    if include_symbols:
        password.append(secrets.choice(string.punctuation))

    # Fill remaining length
    for _ in range(length - len(password)):
        password.append(secrets.choice(chars))

    # Shuffle password
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def hash_password(password: str, salt: Optional[str] = None) -> tuple:
    """
    Hash a password using PBKDF2.

    Args:
        password: Password to hash
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (hash, salt)
    """
    if salt is None:
        salt = secrets.token_hex(32)

    # Use PBKDF2 with SHA256
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,  # iterations
    )

    return key.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        password: Password to verify
        password_hash: Stored password hash
        salt: Salt used for hashing

    Returns:
        True if password matches
    """
    new_hash, _ = hash_password(password, salt)
    return constant_time_compare(new_hash, password_hash)


def generate_hmac(data: str, key: Optional[str] = None) -> str:
    """
    Generate HMAC for data.

    Args:
        data: Data to sign
        key: HMAC key (uses SECRET_KEY if not provided)

    Returns:
        HMAC signature
    """
    if key is None:
        key = settings.SECRET_KEY

    signature = hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256)

    return signature.hexdigest()


def verify_hmac(data: str, signature: str, key: Optional[str] = None) -> bool:
    """
    Verify HMAC signature.

    Args:
        data: Original data
        signature: HMAC signature to verify
        key: HMAC key (uses SECRET_KEY if not provided)

    Returns:
        True if signature is valid
    """
    expected_signature = generate_hmac(data, key)
    return constant_time_compare(expected_signature, signature)


def mask_sensitive_data(data: Any, fields_to_mask: Optional[list] = None) -> Any:
    """
    Mask sensitive data in dictionaries or strings.

    Args:
        data: Data to mask
        fields_to_mask: Fields to mask (uses defaults if not provided)

    Returns:
        Data with sensitive information masked
    """
    if fields_to_mask is None:
        fields_to_mask = [
            "password",
            "token",
            "secret",
            "api_key",
            "private_key",
            "credit_card",
            "ssn",
            "cvv",
            "pin",
        ]

    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if any(field in key.lower() for field in fields_to_mask):
                if isinstance(value, str):
                    # Show first and last character for debugging
                    if len(value) > 4:
                        masked[key] = f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
                    else:
                        masked[key] = "*" * len(value)
                else:
                    masked[key] = "***MASKED***"
            elif isinstance(value, dict):
                masked[key] = mask_sensitive_data(value, fields_to_mask)
            elif isinstance(value, list):
                masked[key] = [
                    mask_sensitive_data(item, fields_to_mask) for item in value
                ]
            else:
                masked[key] = value
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_data(item, fields_to_mask) for item in data]
    else:
        return data


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    import os

    # Remove path separators
    filename = os.path.basename(filename)

    # Remove special characters
    safe_chars = string.ascii_letters + string.digits + "._-"
    filename = "".join(c if c in safe_chars else "_" for c in filename)

    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        filename = name[: max_length - len(ext)] + ext

    return filename


def check_password_strength(password: str) -> dict:
    """
    Check password strength and return analysis.

    Args:
        password: Password to check

    Returns:
        Dictionary with strength analysis
    """
    analysis = {
        "length": len(password),
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digits": any(c.isdigit() for c in password),
        "has_symbols": any(c in string.punctuation for c in password),
        "score": 0,
        "strength": "weak",
        "suggestions": [],
    }

    # Calculate score
    if analysis["length"] >= 8:
        analysis["score"] += 1
    else:
        analysis["suggestions"].append("Use at least 8 characters")

    if analysis["length"] >= 12:
        analysis["score"] += 1

    if analysis["has_uppercase"]:
        analysis["score"] += 1
    else:
        analysis["suggestions"].append("Include uppercase letters")

    if analysis["has_lowercase"]:
        analysis["score"] += 1
    else:
        analysis["suggestions"].append("Include lowercase letters")

    if analysis["has_digits"]:
        analysis["score"] += 1
    else:
        analysis["suggestions"].append("Include numbers")

    if analysis["has_symbols"]:
        analysis["score"] += 1
    else:
        analysis["suggestions"].append("Include special characters")

    # Check for common patterns
    if password.lower() in ["password", "12345678", "qwerty", "abc123"]:
        analysis["score"] = 0
        analysis["suggestions"].append("Avoid common passwords")

    # Determine strength
    if analysis["score"] >= 5:
        analysis["strength"] = "strong"
    elif analysis["score"] >= 3:
        analysis["strength"] = "medium"
    else:
        analysis["strength"] = "weak"

    return analysis


def get_client_ip(request=None) -> Optional[str]:
    """
    Get the client's real IP address from request.

    Args:
        request: Django request object (optional)

    Returns:
        Client IP address or None if not available
    """
    # Try to get request from thread local if not provided
    if request is None:
        try:
            # This is a simplified approach - in production you'd use middleware
            # to store request in thread local
            return None
        except ImportError:
            return None

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        # Try other headers
        ip = request.META.get("HTTP_X_REAL_IP")
        if not ip:
            ip = request.META.get("REMOTE_ADDR", "127.0.0.1")

    return ip


def get_current_user():
    """
    Get the currently authenticated user from the request context.

    Returns:
        User object or None if not authenticated
    """
    try:
        # This would require a middleware to store the request in thread local
        # For now, return None as a safe default
        # In production, you'd implement CurrentUserMiddleware
        return None
    except ImportError:
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private.

    Args:
        ip: IP address to check

    Returns:
        True if IP is private
    """
    import ipaddress

    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def generate_csrf_token() -> str:
    """
    Generate a CSRF token.

    Returns:
        CSRF token
    """
    return get_random_string(32)


def time_constant_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal
    """
    return constant_time_compare(a, b)
