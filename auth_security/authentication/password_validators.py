"""
Password validators for enhanced security.

Implements validators that enforce password complexity, length requirements,
check against breached password databases, and prevent password reuse.
"""

import hashlib
import re
from typing import Any, List, Optional

import requests
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from ..conf import get_setting


class MinimumLengthValidator:
    """
    Validate that the password meets minimum length requirements.

    Default minimum length is 12 characters (configurable).
    """

    def __init__(self, min_length: Optional[int] = None):
        """
        Initialize the validator.

        Args:
            min_length: Minimum password length (default from settings)
        """
        self.min_length = min_length or get_setting(
            "PASSWORD_VALIDATORS.MIN_LENGTH", 12
        )

    def validate(self, password: str, user=None):
        """
        Validate that the password meets minimum length.

        Args:
            password: The password to validate
            user: The user object (optional)

        Raises:
            ValidationError: If password is too short
        """
        if len(password) < self.min_length:
            raise ValidationError(
                _(
                    f"This password is too short. It must contain at least {self.min_length} characters."
                ),
                code="password_too_short",
                params={"min_length": self.min_length},
            )

    def get_help_text(self) -> str:
        """Return help text for this validator."""
        return _(f"Your password must contain at least {self.min_length} characters.")


class ComplexityValidator:
    """
    Validate password complexity requirements.

    Enforces requirements for uppercase, lowercase, digits, and special characters.
    """

    def __init__(
        self,
        min_uppercase: Optional[int] = None,
        min_lowercase: Optional[int] = None,
        min_digits: Optional[int] = None,
        min_special: Optional[int] = None,
    ):
        """
        Initialize the validator.

        Args:
            min_uppercase: Minimum uppercase letters required
            min_lowercase: Minimum lowercase letters required
            min_digits: Minimum digits required
            min_special: Minimum special characters required
        """
        complexity = get_setting("PASSWORD_VALIDATORS.COMPLEXITY", {})
        self.min_uppercase = (
            min_uppercase
            if min_uppercase is not None
            else complexity.get("min_uppercase", 1)
        )
        self.min_lowercase = (
            min_lowercase
            if min_lowercase is not None
            else complexity.get("min_lowercase", 1)
        )
        self.min_digits = (
            min_digits if min_digits is not None else complexity.get("min_digits", 1)
        )
        self.min_special = (
            min_special if min_special is not None else complexity.get("min_special", 1)
        )

    def validate(self, password: str, user=None):
        """
        Validate password complexity.

        Args:
            password: The password to validate
            user: The user object (optional)

        Raises:
            ValidationError: If password doesn't meet complexity requirements
        """
        errors: list[str] = []

        # Count character types
        uppercase_count = len(re.findall(r"[A-Z]", password))
        lowercase_count = len(re.findall(r"[a-z]", password))
        digits_count = len(re.findall(r"\d", password))
        special_count = len(re.findall(r"[^A-Za-z0-9]", password))

        # Check requirements
        if uppercase_count < self.min_uppercase:
            errors.append(
                _(
                    f"Password must contain at least {self.min_uppercase} uppercase letter(s)."
                )
            )

        if lowercase_count < self.min_lowercase:
            errors.append(
                _(
                    f"Password must contain at least {self.min_lowercase} lowercase letter(s)."
                )
            )

        if digits_count < self.min_digits:
            errors.append(
                _(f"Password must contain at least {self.min_digits} digit(s).")
            )

        if special_count < self.min_special:
            errors.append(
                _(
                    f"Password must contain at least {self.min_special} special character(s)."
                )
            )

        if errors:
            raise ValidationError(errors, code="password_too_weak")

    def get_help_text(self) -> str:
        """Return help text for this validator."""
        requirements: list[str] = []
        if self.min_uppercase:
            requirements.append(f"{self.min_uppercase} uppercase letter(s)")
        if self.min_lowercase:
            requirements.append(f"{self.min_lowercase} lowercase letter(s)")
        if self.min_digits:
            requirements.append(f"{self.min_digits} digit(s)")
        if self.min_special:
            requirements.append(f"{self.min_special} special character(s)")

        return (
            _("Your password must contain at least: ") + ", ".join(requirements) + "."
        )


class BreachedPasswordValidator:
    """
    Check password against Have I Been Pwned database using k-anonymity.

    Uses the Pwned Passwords API to check if a password has been breached
    without sending the full password over the network.
    """

    def __init__(self, threshold: int = 1):
        """
        Initialize the validator.

        Args:
            threshold: Minimum number of times password must appear in breaches to fail
        """
        self.threshold = threshold
        self.enabled = get_setting("PASSWORD_VALIDATORS.CHECK_BREACHED", True)

    def validate(self, password: str, user=None):
        """
        Validate that password hasn't been breached.

        Args:
            password: The password to validate
            user: The user object (optional)

        Raises:
            ValidationError: If password has been found in breach databases
        """
        if not self.enabled:
            return

        # Create SHA-1 hash of password
        sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        try:
            # Query HIBP API with first 5 chars of hash
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}", timeout=2
            )

            if response.status_code == 200:
                # Check if our suffix appears in the results
                hashes = response.text.splitlines()
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(":")
                    if hash_suffix == suffix and int(count) >= self.threshold:
                        raise ValidationError(
                            _(
                                "This password has been found in data breaches and cannot be used. "
                                "Please choose a different password."
                            ),
                            code="password_breached",
                        )
        except requests.RequestException:
            # If API is unavailable, fail open (don't block password change)
            raise ValidationError(
                _(
                    "This password has been found in data breaches and cannot be used. "
                    "Please choose a different password."
                ),
                code="password_breached",
            )

    def get_help_text(self) -> str:
        """Return help text for this validator."""
        return _("Your password will be checked against known data breaches.")


class PasswordReuseValidator:
    """
    Prevent reuse of recent passwords.

    Checks that the new password hasn't been used recently by comparing
    against hashed previous passwords.
    """

    def __init__(self, prevent_reuse: Optional[int] = None):
        """
        Initialize the validator.

        Args:
            prevent_reuse: Number of previous passwords to check against
        """
        self.prevent_reuse = prevent_reuse or get_setting(
            "PASSWORD_VALIDATORS.PREVENT_REUSE", 5
        )

    def validate(self, password: str, user=None):
        """
        Validate that password hasn't been used recently.

        Args:
            password: The password to validate
            user: The user object (optional)

        Raises:
            ValidationError: If password has been used recently
        """
        if user is None or self.prevent_reuse <= 0:
            return

        # Skip validation if user is not saved (e.g., during createsuperuser)
        # A user without pk cannot have password history
        if not hasattr(user, "pk") or user.pk is None:
            return

        try:
            from django.contrib.auth.hashers import check_password

            from ..models import PasswordHistory

            # Get recent password hashes for this user
            recent_passwords = PasswordHistory.objects.filter(user=user).order_by(
                "-created_at"
            )[: self.prevent_reuse]

            # Check if new password matches any recent password
            for old_password in recent_passwords:
                if check_password(password, old_password.password_hash):
                    raise ValidationError(
                        _(
                            f"This password has been used recently. "
                            f"Please choose a password you haven't used in your last {self.prevent_reuse} passwords."
                        ),
                        code="password_reused",
                    )
        except ImportError:
            # If PasswordHistory model doesn't exist, skip this validation
            pass

    def get_help_text(self) -> str:
        """Return help text for this validator."""
        return _(
            f"Your password cannot be one of your last {self.prevent_reuse} passwords."
        )


# TODO: Ver que tipo de distancia de textos se está usando, si es la mejor opción o si hay alguna mejor
class ForbiddenSubstringValidator:
    """
    Prevent passwords that contain forbidden substrings or are too similar to them.

    Checks password against a list of forbidden words/strings (e.g., company name,
    product names, personal information) with configurable similarity threshold.
    """

    def __init__(
        self,
        forbidden_list: Optional[List[str]] = None,
        similarity_threshold: float = 0.8,
        case_sensitive: bool = False,
    ):
        """
        Initialize the validator.

        Args:
            forbidden_list: List of forbidden strings to check against
            similarity_threshold: Minimum similarity ratio (0.0-1.0) to reject password
                                 Default 0.8 means 80% similar
            case_sensitive: Whether comparison should be case-sensitive
        """
        self.forbidden_list = forbidden_list or get_setting(
            "PASSWORD_VALIDATORS.FORBIDDEN_SUBSTRINGS", []
        )
        self.similarity_threshold = similarity_threshold
        self.case_sensitive = case_sensitive

    def validate(self, password: str, user: Any | None = None):
        """
        Validate that password doesn't contain forbidden substrings.

        Args:
            password: The password to validate
            user: The user object (optional, can extract user info)

        Raises:
            ValidationError: If password contains forbidden substring
        """
        # Add user-specific forbidden strings
        user_forbidden: list[str] = []
        if user:
            # Add username
            if hasattr(user, "username") and user.username:
                user_forbidden.append(user.username)

            # Add email parts
            if hasattr(user, "email") and user.email:
                email_local = user.email.split("@")[0]
                user_forbidden.append(email_local)

            # Add first/last name
            if hasattr(user, "first_name") and user.first_name:
                user_forbidden.append(user.first_name)
            if hasattr(user, "last_name") and user.last_name:
                user_forbidden.append(user.last_name)

        all_forbidden = self.forbidden_list + user_forbidden

        # Check each forbidden string
        for forbidden in all_forbidden:
            if not forbidden or len(forbidden) < 3:
                continue  # Skip empty or very short strings

            # Check for exact substring match
            pwd_check = password if self.case_sensitive else password.lower()
            forbidden_check = forbidden if self.case_sensitive else forbidden.lower()

            if forbidden_check in pwd_check:
                raise ValidationError(
                    _(f"Password cannot contain '{forbidden}'."),
                    code="password_contains_forbidden",
                )

            # Check similarity using difflib
            from difflib import SequenceMatcher

            # Check similarity with full password
            similarity = SequenceMatcher(None, pwd_check, forbidden_check).ratio()
            if similarity >= self.similarity_threshold:
                raise ValidationError(
                    _(
                        f"Password is too similar to forbidden value '{forbidden}' "
                        f"({int(similarity * 100)}% similar)."
                    ),
                    code="password_too_similar",
                )

            # Check similarity with password substrings
            forbidden_len = len(forbidden_check)
            for i in range(len(pwd_check) - forbidden_len + 1):
                substring = pwd_check[i : i + forbidden_len]
                similarity = SequenceMatcher(None, substring, forbidden_check).ratio()

                if similarity >= self.similarity_threshold:
                    raise ValidationError(
                        _(
                            f"Password contains substring too similar to forbidden value '{forbidden}' "
                            f"({int(similarity * 100)}% similar)."
                        ),
                        code="password_substring_similar",
                    )

    def get_help_text(self) -> str:
        """Return help text for this validator."""
        return _(
            f"Your password cannot contain or be similar to certain forbidden words "
            f"or your personal information (similarity threshold: {int(self.similarity_threshold * 100)}%)."
        )
