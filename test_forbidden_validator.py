#!/usr/bin/env python
"""
Test script for ForbiddenSubstringValidator.

This script demonstrates the forbidden substring validation with similarity checking.
"""

import os

import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')
django.setup()

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from auth_security.authentication.password_validators import ForbiddenSubstringValidator


def test_forbidden_validator():
    """Test the ForbiddenSubstringValidator with various scenarios."""

    print("=" * 80)
    print("Testing ForbiddenSubstringValidator")
    print("=" * 80)
    print()

    # Create a test user
    user = User(
        username='johndoe',
        email='john.doe@example.com',
        first_name='John',
        last_name='Doe'
    )

    # Initialize validator with some forbidden words
    validator = ForbiddenSubstringValidator(
        forbidden_list=['company', 'acme', 'password'],
        similarity_threshold=0.8,
        case_sensitive=False
    )

    test_passwords = [
        # (password, description, should_pass)
        ('MySecure123!Pass', 'Valid strong password', True),
        ('Company123!', 'Contains forbidden word "company"', False),
        ('C0mpany123!', 'Similar to "company" (80%+ similar)', False),
        ('Acme1234!Pass', 'Contains forbidden word "acme"', False),
        ('AcmeXYZ123!', 'Contains "acme" at start', False),
        ('johndoe123!', 'Contains username', False),
        ('JohnDoe123!', 'Contains username (case insensitive)', False),
        ('john.doe123!', 'Contains email local part', False),
        ('John1234!', 'Contains first name', False),
        ('Doe12345!', 'Contains last name', False),
        ('MyJ0hn123!Pass', 'Similar to first name', False),
        ('CompletelyDifferent123!', 'No forbidden strings', True),
        ('Xpendit2025!', 'No forbidden strings', True),
    ]

    print(f"User Information:")
    print(f"  Username: {user.username}")
    print(f"  Email: {user.email}")
    print(f"  First Name: {user.first_name}")
    print(f"  Last Name: {user.last_name}")
    print()

    print(f"Forbidden List: {validator.forbidden_list}")
    print(f"Similarity Threshold: {validator.similarity_threshold * 100}%")
    print()

    print("-" * 80)
    print(f"{'Password':<30} {'Expected':<15} {'Result':<15} {'Status':<10}")
    print("-" * 80)

    for password, description, should_pass in test_passwords:
        try:
            validator.validate(password, user)
            result = "✓ PASSED"
            status = "✓" if should_pass else "✗ FAIL"
        except ValidationError as e:
            result = f"✗ REJECTED"
            status = "✓" if not should_pass else "✗ FAIL"
            error_msg = ', '.join(e.messages)

        expected = "PASS" if should_pass else "REJECT"

        print(f"{password:<30} {expected:<15} {result:<15} {status:<10}")

        if not should_pass:
            try:
                validator.validate(password, user)
            except ValidationError as e:
                print(f"  → Reason: {', '.join(e.messages)}")
        print()

    print("-" * 80)
    print()

    # Test similarity detection
    print("=" * 80)
    print("Similarity Detection Examples")
    print("=" * 80)
    print()

    from difflib import SequenceMatcher

    test_pairs = [
        ('company', 'Company'),
        ('company', 'C0mpany'),
        ('company', 'Kompany'),
        ('johndoe', 'j0hndoe'),
        ('johndoe', 'johndo3'),
        ('acme', 'Acme2024'),
    ]

    for word1, word2 in test_pairs:
        similarity = SequenceMatcher(None, word1.lower(), word2.lower()).ratio()
        similar = similarity >= 0.8
        print(f"{word1:<15} vs {word2:<15} → {similarity*100:5.1f}% similar  {'[BLOCKED]' if similar else '[ALLOWED]'}")

    print()

if __name__ == '__main__':
    test_forbidden_validator()
