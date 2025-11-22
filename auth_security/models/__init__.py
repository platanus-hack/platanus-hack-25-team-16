"""Security models for authentication and audit tracking."""

from .password import PasswordHistory
from .suspicious import SuspiciousLogin

__all__ = [
    'PasswordHistory',
    'SuspiciousLogin',
]
