# Auth Security - Django Authentication & Session Security

Part of the Django Security Library for ISO 27001 and OWASP Compliance.

## Overview

`auth_security` is a Django app that provides comprehensive authentication and session security features:

- **Password Validators**: Enforce password complexity, length requirements, and check against breached passwords
- **Brute Force Protection**: Account lockout and exponential delays after failed login attempts
- **Session Security**: Absolute and inactivity timeouts, IP binding, session fixation protection
- **MFA Support**: Ready-to-use hooks and decorators for Multi-Factor Authentication
- **Suspicious Login Detection**: Automatic detection and notification of unusual login patterns
- **Comprehensive Audit Trail**: Track all login attempts, lockouts, and security events

## Installation

1. Add `auth_security` to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    'auth_security',
]
```

2. Add the security middlewares (order matters):

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'auth_security.middleware.LoginProtectionMiddleware',  # Add this
    'auth_security.middleware.SessionSecurityMiddleware',  # Add this
    'auth_security.middleware.mfa.MFAMiddleware',          # Add this (optional, if using MFA)
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

3. Configure password validators:

```python
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "auth_security.authentication.password_validators.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {
        "NAME": "auth_security.authentication.password_validators.ComplexityValidator",
        "OPTIONS": {
            "min_uppercase": 1,
            "min_lowercase": 1,
            "min_digits": 1,
            "min_special": 1,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "auth_security.authentication.password_validators.BreachedPasswordValidator",
    },
    {
        "NAME": "auth_security.authentication.password_validators.PasswordReuseValidator",
    },
]
```

4. Run migrations:

```bash
python manage.py migrate auth_security
```

## Configuration

Add the following to your `settings.py`:

```python
DJANGO_SEC = {
    # Authentication Protection
    'AUTH_PROTECTION': {
        'MAX_LOGIN_ATTEMPTS': 5,           # Lock account after 5 failed attempts
        'LOCKOUT_DURATION': 900,           # 15 minutes lockout
        'LOCKOUT_STRATEGY': 'exponential', # 'fixed' or 'exponential'
        'DELAY_STRATEGY': 'exponential',   # Add delays to failed logins
        'BASE_DELAY_SECONDS': 1,           # Starting delay for exponential backoff
        'NOTIFICATION': {
            'EMAIL_ON_LOCKOUT': True,
            'EMAIL_ON_SUSPICIOUS_LOGIN': True,
            'WEBHOOK_URL': None,           # Optional webhook for notifications
        }
    },

    # Session Security
    'SESSION_SECURITY': {
        'ABSOLUTE_TIMEOUT': 28800,         # 8 hours max session duration
        'INACTIVITY_TIMEOUT': 3600,        # 1 hour inactivity timeout
        'ROTATE_ON_LOGIN': True,           # Prevent session fixation attacks
        'BIND_TO_IP': True,                # Detect IP changes
        'BIND_TO_USER_AGENT': False,       # Detect user agent changes (can cause issues)
    },

    # Multi-Factor Authentication
    'MFA': {
        'ENABLED': False,                  # Set to True to enable MFA
        'REQUIRED_FOR_STAFF': True,        # Require MFA for staff users
        'REQUIRED_FOR_SUPERUSERS': True,   # Require MFA for superusers
        'GRACE_PERIOD_DAYS': 7,            # Days to set up MFA before enforcing
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
        'CHECK_BREACHED': True,            # Check against Have I Been Pwned
        'PREVENT_REUSE': 5,                # Number of previous passwords to check
    },
}

# Required for rate limiting and lockout tracking
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Session cookies configuration
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # Set to True in production with HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 3600  # 1 hour
```

## Usage

### Using Decorators

#### Require MFA for sensitive views:

```python
from auth_security.decorators import require_mfa

@require_mfa(methods=['totp', 'webauthn'])
def delete_account(request):
    # This view requires MFA completion
    pass
```

#### Mark sensitive operations:

```python
from auth_security.decorators import sensitive_operation

@sensitive_operation(audit=True, require_recent_auth=True)
def change_password(request):
    # Requires recent authentication
    pass
```

#### Rate limit endpoints:

```python
from auth_security.decorators import rate_limited

@rate_limited(key='user', limit='5/m')
def api_endpoint(request):
    # Limited to 5 requests per minute per user
    pass
```

#### IP whitelist:

```python
from auth_security.decorators import ip_whitelist

@ip_whitelist(['192.168.1.0/24', '10.0.0.1'])
def admin_dashboard(request):
    # Only accessible from specified IPs
    pass
```

### Using Signals

Connect to security events:

```python
from django.dispatch import receiver
from auth_security.signals import (
    account_locked,
    suspicious_login_detected,
    mfa_completed,
)

@receiver(account_locked)
def handle_account_locked(sender, user, lockout, **kwargs):
    # Send notification to security team
    print(f"Account locked: {user.username}")

@receiver(suspicious_login_detected)
def handle_suspicious_login(sender, suspicious_login, request, **kwargs):
    # Log suspicious activity
    print(f"Suspicious login: {suspicious_login.reason}")
```

### Checking Account Status

```python
from auth_security.middleware.auth_protection import check_account_locked

# Check if account is locked
lockout = check_account_locked(user)
if lockout:
    print(f"Account locked until {lockout.locked_until}")
```

### Session Information

```python
from auth_security.middleware.session_security import get_session_info

# Get session security information
info = get_session_info(request)
print(f"Session age: {info['session_age_seconds']} seconds")
print(f"Time until timeout: {info['time_until_inactivity_timeout']} seconds")
```

### MFA Management

```python
from auth_security.middleware.mfa import mark_mfa_completed, is_mfa_completed

# After successful MFA verification
mark_mfa_completed(request, device_id=device.id)

# Check if MFA is completed
if is_mfa_completed(request):
    # User has completed MFA
    pass
```

## Models

### LoginAttempt

Tracks all login attempts (successful and failed):

```python
from auth_security.models import LoginAttempt

# Get recent failed attempts
failed_attempts = LoginAttempt.objects.filter(
    user=user,
    success=False,
    timestamp__gte=timezone.now() - timedelta(hours=1)
)
```

### AccountLockout

Tracks account lockouts:

```python
from auth_security.models import AccountLockout

# Get active lockouts
active_lockouts = AccountLockout.objects.filter(
    user=user,
    is_active=True
)

# Manually unlock account
lockout.unlock(unlocked_by=admin_user)
```

### SuspiciousLogin

Tracks suspicious login attempts:

```python
from auth_security.models import SuspiciousLogin

# Get unreviewed suspicious logins
suspicious = SuspiciousLogin.objects.filter(
    reviewed=False
)
```

### MFADevice

Manage user MFA devices:

```python
from auth_security.models import MFADevice

# Get user's active MFA devices
devices = MFADevice.objects.filter(
    user=user,
    is_active=True
)

# Register new TOTP device
device = MFADevice.objects.create(
    user=user,
    name="Google Authenticator",
    method='totp',
    is_primary=True,
    secret=totp_secret,
)
```

### PasswordHistory

Tracks password history for reuse prevention:

```python
from auth_security.models import PasswordHistory

# Save password to history
PasswordHistory.objects.create(
    user=user,
    password_hash=user.password,
)
```

## Security Signals

Available signals for custom handling:

- `account_locked`: Fired when account is locked
- `suspicious_login_detected`: Fired when suspicious login is detected
- `login_attempt_recorded`: Fired on every login attempt
- `mfa_required`: Fired when MFA is required
- `mfa_completed`: Fired when MFA verification succeeds
- `mfa_failed`: Fired when MFA verification fails
- `password_changed`: Fired when password is changed
- `session_expired`: Fired when session expires
- `session_hijacking_detected`: Fired when session hijacking is suspected

## Admin Interface

The app provides Django admin integration for all models:

- View and manage login attempts
- Review suspicious logins
- Manage account lockouts
- View MFA devices
- Audit password history

## Testing

```bash
python manage.py test auth_security
```

## Security Best Practices

1. **Always use HTTPS in production**: Set `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True`

2. **Use Redis for caching in production**: Replace LocMemCache with Redis for better performance and persistence

3. **Configure email notifications**: Set up proper email backend for lockout and suspicious login notifications

4. **Enable MFA for privileged accounts**: Set `MFA.ENABLED = True` and require it for staff/superusers

5. **Monitor security logs**: Regularly review LoginAttempt and SuspiciousLogin records

6. **Set up IP geolocation**: Integrate with MaxMind or similar service for better suspicious login detection

7. **Use strong password policies**: Keep the default complexity requirements or make them stricter

## Compliance

This app helps meet the following compliance requirements:

### OWASP Top 10 2021

- **A07: Identification and Authentication Failures**
  - Brute force protection
  - Strong password policies
  - MFA support
  - Session management

### ISO 27001

- **A.9.2: User access management**
  - Account lockout policies
  - Authentication logging

- **A.9.4: System and application access control**
  - Session timeout enforcement
  - MFA capabilities

- **A.12.4: Logging and monitoring**
  - Comprehensive audit trail
  - Security event logging

## License

MIT License

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the project repository.
