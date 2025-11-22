"""
Auth Security - Authentication & Session Security

Part of Django Security Library for ISO 27001 and OWASP Compliance.

This app provides:
- Password validators with complexity and breach checking
- Brute force protection and account lockout
- Session security with timeout and fixation prevention
- MFA-ready hooks and decorators
- Suspicious login detection and notifications
"""

__version__ = "0.1.0"
__author__ = "Django Security Team"

default_app_config = "auth_security.apps.AuthSecurityConfig"
