"""Configuration and settings for django_security."""

from typing import Any, Dict

# Default security settings
SECURE_DEFAULTS: Dict[str, Any] = {
    # Authentication & Session Security
    'AUTH_PROTECTION': {
        'MAX_LOGIN_ATTEMPTS': 5,
        'LOCKOUT_DURATION': 900,  # 15 minutes
        'LOCKOUT_STRATEGY': 'exponential',  # fixed, exponential
        'DELAY_STRATEGY': 'exponential',  # none, fixed, exponential
        'BASE_DELAY_SECONDS': 1,  # Base delay for exponential backoff
        'NOTIFICATION': {
            'EMAIL_ON_LOCKOUT': True,
            'EMAIL_ON_SUSPICIOUS_LOGIN': True,  # IP/geo unknown
            'WEBHOOK_URL': None,  # Optional webhook for notifications
        }
    },
    'SESSION_SECURITY': {
        'ABSOLUTE_TIMEOUT': 28800,  # 8 hours max
        'INACTIVITY_TIMEOUT': 3600,  # 1 hour inactivity
        'ROTATE_ON_LOGIN': True,  # Prevent session fixation
        'BIND_TO_IP': True,  # Validate IP doesn't change
        'BIND_TO_USER_AGENT': False,  # Optional, can cause issues
    },
    'MFA': {
        'ENABLED': False,
        'REQUIRED_FOR_STAFF': True,
        'REQUIRED_FOR_SUPERUSERS': True,
        'GRACE_PERIOD_DAYS': 7,  # Days before MFA is enforced
        'BACKUP_CODES_COUNT': 10,
        'METHODS': ['totp', 'webauthn', 'sms'],
    },
    # Password Validation
    'PASSWORD_VALIDATORS': {
        'MIN_LENGTH': 12,
        'COMPLEXITY': {
            'min_uppercase': 1,
            'min_lowercase': 1,
            'min_digits': 1,
            'min_special': 1,
        },
        'CHECK_BREACHED': True,  # Check against Have I Been Pwned
        'PREVENT_REUSE': 5,  # Number of previous passwords to check
    },
}


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a security setting from Django settings or use default.

    Args:
        key: Dotted path to the setting (e.g., 'AUTH_PROTECTION.MAX_LOGIN_ATTEMPTS')
        default: Default value if setting is not found

    Returns:
        The setting value or default
    """
    from django.conf import settings

    django_sec = getattr(settings, 'DJANGO_SEC', {})

    # Navigate through nested keys
    keys = key.split('.')
    value = django_sec

    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        else:
            break

    if value is None:
        # Try to get from SECURE_DEFAULTS
        value = SECURE_DEFAULTS
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                break

    return value if value is not None else default
