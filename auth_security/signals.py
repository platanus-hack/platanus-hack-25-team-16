"""
Security-related Django signals.

These signals are fired when security events occur, allowing applications
to hook into security workflows for custom handling, logging, or notifications.
"""

from django.dispatch import Signal

# Authentication signals
account_locked = Signal()
"""
Fired when a user account is locked due to failed login attempts.

Provides arguments:
    sender: The class that sent the signal
    user: The User instance that was locked
    lockout: The AccountLockout instance
"""

suspicious_login_detected = Signal()
"""
Fired when a suspicious login is detected.

Provides arguments:
    sender: The class that sent the signal
    suspicious_login: The SuspiciousLogin instance
    request: The HttpRequest object
"""

login_attempt_recorded = Signal()
"""
Fired when any login attempt is recorded (success or failure).

Provides arguments:
    sender: The class that sent the signal
    attempt: The LoginAttempt instance
    request: The HttpRequest object
"""

mfa_required = Signal()
"""
Fired when MFA is required for a user.

Provides arguments:
    sender: The class that sent the signal
    user: The User instance
    request: The HttpRequest object
"""

mfa_completed = Signal()
"""
Fired when MFA verification is completed successfully.

Provides arguments:
    sender: The class that sent the signal
    user: The User instance
    device: The MFADevice instance used
    request: The HttpRequest object
"""

mfa_failed = Signal()
"""
Fired when MFA verification fails.

Provides arguments:
    sender: The class that sent the signal
    user: The User instance
    device: The MFADevice instance (if any)
    request: The HttpRequest object
"""

password_changed = Signal()
"""
Fired when a user changes their password.

Provides arguments:
    sender: The class that sent the signal
    user: The User instance
    request: The HttpRequest object (if available)
"""

# Session signals
session_expired = Signal()
"""
Fired when a session expires (inactivity or absolute timeout).

Provides arguments:
    sender: The class that sent the signal
    user: The User instance
    session_key: The expired session key
    reason: Why the session expired ('inactivity' or 'absolute_timeout')
"""

session_hijacking_detected = Signal()
"""
Fired when potential session hijacking is detected.

Provides arguments:
    sender: The class that sent the signal
    user: The User instance
    session_key: The session key
    reason: Why hijacking was suspected (e.g., 'ip_mismatch', 'user_agent_mismatch')
"""
