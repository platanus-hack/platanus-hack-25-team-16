"""
Middleware for login protection against brute force attacks.

Tracks login attempts, implements account lockouts, adds delays to failed logins,
and notifies users of suspicious activity.
"""

import time
from datetime import timedelta
from typing import Optional

from django.contrib.auth import user_logged_in, user_login_failed
from django.contrib.auth.signals import user_logged_out
from django.core.cache import cache
from django.core.mail import send_mail
from django.dispatch import receiver
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.utils.translation import gettext as _

from ..conf import get_setting
from ..models import LoginAttempt, AccountLockout, SuspiciousLogin
from ..signals import (
    account_locked,
    suspicious_login_detected,
    login_attempt_recorded,
)
from ..utils.ip import get_client_ip


class LoginProtectionMiddleware:
    """
    Middleware to protect against brute force login attacks.

    Features:
    - Tracks all login attempts
    - Implements account lockout after X failed attempts
    - Adds increasing delays to failed login attempts
    - Detects and flags suspicious logins
    - Sends notifications for security events
    """

    def __init__(self, get_response):
        self.get_response = get_response

        # Load configuration
        auth_config = get_setting('AUTH_PROTECTION', {})
        self.max_attempts = auth_config.get('MAX_LOGIN_ATTEMPTS', 5)
        self.lockout_duration = auth_config.get('LOCKOUT_DURATION', 900)
        self.lockout_strategy = auth_config.get('LOCKOUT_STRATEGY', 'exponential')
        self.delay_strategy = auth_config.get('DELAY_STRATEGY', 'exponential')
        self.base_delay = auth_config.get('BASE_DELAY_SECONDS', 1)

        notification_config = auth_config.get('NOTIFICATION', {})
        self.email_on_lockout = notification_config.get('EMAIL_ON_LOCKOUT', True)
        self.email_on_suspicious = notification_config.get('EMAIL_ON_SUSPICIOUS_LOGIN', True)
        self.webhook_url = notification_config.get('WEBHOOK_URL')

        # Register signal handlers
        self._register_signals()

    def __call__(self, request: HttpRequest):
        """Process the request."""
        response = self.get_response(request)
        return response

    def _register_signals(self):
        """Register Django auth signals for tracking."""
        # Note: These are registered per instance, but Django signals handle duplicates
        user_logged_in.connect(self._handle_successful_login, dispatch_uid='security_login_success')
        user_login_failed.connect(self._handle_failed_login, dispatch_uid='security_login_failed')
        user_logged_out.connect(self._handle_logout, dispatch_uid='security_logout')

    def _handle_successful_login(self, sender, request, user, **kwargs):
        """Handle successful login."""
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Record login attempt
        attempt = LoginAttempt.objects.create(
            user=user,
            username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
        )

        # Clear failed login cache for this user
        self._clear_failed_attempts_cache(user.username, ip_address)

        # Check for suspicious login
        self._check_suspicious_login(attempt, request)

        # Send signal
        login_attempt_recorded.send(
            sender=self.__class__,
            attempt=attempt,
            request=request,
        )

    def _handle_failed_login(self, sender, credentials, request, **kwargs):
        """Handle failed login attempt."""
        username = credentials.get('username', '')
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Try to get user
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass

        # Check if account is locked
        if user and self._is_account_locked(user):
            failure_reason = 'account_locked'
        else:
            failure_reason = 'invalid_credentials'

        # Record failed attempt
        attempt = LoginAttempt.objects.create(
            user=user,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            failure_reason=failure_reason,
        )

        # Increment failed attempts counter
        failed_count = self._increment_failed_attempts(username, ip_address)

        # Check if we should lock the account
        if user and failed_count >= self.max_attempts:
            self._lock_account(user, ip_address, failed_count)

        # Apply delay strategy
        self._apply_login_delay(failed_count)

        # Send signal
        login_attempt_recorded.send(
            sender=self.__class__,
            attempt=attempt,
            request=request,
        )

    def _handle_logout(self, sender, request, user, **kwargs):
        """Handle logout - can be used for session rotation."""
        pass

    def _is_account_locked(self, user) -> bool:
        """Check if user account is currently locked."""
        active_lockouts = AccountLockout.objects.filter(
            user=user,
            is_active=True,
            locked_until__gt=timezone.now()
        )

        return active_lockouts.exists()

    def _lock_account(self, user, ip_address: str, failed_count: int):
        """Lock user account after too many failed attempts."""
        # Calculate lockout duration based on strategy
        if self.lockout_strategy == 'exponential':
            # Exponential backoff: 15 min, 30 min, 1 hour, 2 hours, etc.
            lockout_attempts = AccountLockout.objects.filter(user=user).count()
            duration = self.lockout_duration * (2 ** lockout_attempts)
        else:
            duration = self.lockout_duration

        locked_until = timezone.now() + timedelta(seconds=duration)

        # Create lockout record
        lockout = AccountLockout.objects.create(
            user=user,
            locked_until=locked_until,
            reason=f"Too many failed login attempts ({failed_count})",
            failed_attempts_count=failed_count,
            ip_address=ip_address,
        )

        # Send signal
        account_locked.send(
            sender=self.__class__,
            user=user,
            lockout=lockout,
        )

        # Send notification
        if self.email_on_lockout:
            self._send_lockout_notification(user, lockout)

    def _increment_failed_attempts(self, username: str, ip_address: str) -> int:
        """Increment and return failed login attempts counter."""
        # Use both username and IP for the key
        cache_key = f'login_attempts:{username}:{ip_address}'
        failed_count = cache.get(cache_key, 0) + 1

        # Store for lockout duration
        cache.set(cache_key, failed_count, self.lockout_duration)

        return failed_count

    def _clear_failed_attempts_cache(self, username: str, ip_address: str):
        """Clear failed attempts cache after successful login."""
        cache_key = f'login_attempts:{username}:{ip_address}'
        cache.delete(cache_key)

    def _apply_login_delay(self, failed_count: int):
        """Apply delay to slow down brute force attempts."""
        if self.delay_strategy == 'exponential':
            # Exponential delay: 1s, 2s, 4s, 8s, 16s
            delay = self.base_delay * (2 ** (failed_count - 1))
            delay = min(delay, 30)  # Cap at 30 seconds
        elif self.delay_strategy == 'fixed':
            delay = self.base_delay
        else:
            return  # No delay

        time.sleep(delay)

    def _check_suspicious_login(self, attempt: LoginAttempt, request: HttpRequest):
        """Check if login is suspicious and flag it."""
        user = attempt.user
        suspicious_reasons = []

        # Check for new IP address
        if self._is_new_ip(user, attempt.ip_address):
            suspicious_reasons.append(('new_ip', {'ip': attempt.ip_address}))

        # Check for login after multiple failures
        recent_failures = LoginAttempt.objects.filter(
            user=user,
            success=False,
            timestamp__gte=timezone.now() - timedelta(minutes=30)
        ).count()

        if recent_failures >= 3:
            suspicious_reasons.append(
                ('after_failures', {'failure_count': recent_failures})
            )

        # If suspicious, create records and notify
        for reason, details in suspicious_reasons:
            suspicious = SuspiciousLogin.objects.create(
                user=user,
                login_attempt=attempt,
                reason=reason,
                details=details,
            )

            # Send signal
            suspicious_login_detected.send(
                sender=self.__class__,
                suspicious_login=suspicious,
                request=request,
            )

            # Send notification
            if self.email_on_suspicious:
                self._send_suspicious_login_notification(user, suspicious)

    def _is_new_ip(self, user, ip_address: str) -> bool:
        """Check if this is a new IP address for the user."""
        # Check if user has logged in from this IP before
        previous_login = LoginAttempt.objects.filter(
            user=user,
            ip_address=ip_address,
            success=True,
        ).exists()

        return not previous_login

    def _send_lockout_notification(self, user, lockout: AccountLockout):
        """Send email notification about account lockout."""
        if not user.email:
            return

        subject = _("Account Security Alert: Your account has been locked")
        message = _(
            f"Hello {user.username},\n\n"
            f"Your account has been temporarily locked due to multiple failed login attempts.\n\n"
            f"Locked until: {lockout.locked_until}\n"
            f"IP Address: {lockout.ip_address}\n\n"
            f"If this was not you, please contact support immediately.\n\n"
            f"If this was you, please wait until the lockout expires or contact support to unlock your account."
        )

        try:
            send_mail(
                subject,
                message,
                None,  # Use DEFAULT_FROM_EMAIL
                [user.email],
                fail_silently=True,
            )
        except Exception:
            pass  # Don't let email failures break the flow

    def _send_suspicious_login_notification(self, user, suspicious: SuspiciousLogin):
        """Send email notification about suspicious login."""
        if not user.email:
            return

        attempt = suspicious.login_attempt
        subject = _("Security Alert: Unusual login to your account")
        message = _(
            f"Hello {user.username},\n\n"
            f"We detected a login to your account that looks unusual.\n\n"
            f"Time: {attempt.timestamp}\n"
            f"IP Address: {attempt.ip_address}\n"
            f"Location: {attempt.geo_location or 'Unknown'}\n"
            f"Reason: {suspicious.get_reason_display()}\n\n"
            f"If this was you, you can ignore this email.\n"
            f"If this was not you, please change your password immediately and contact support."
        )

        try:
            send_mail(
                subject,
                message,
                None,
                [user.email],
                fail_silently=True,
            )
            suspicious.notified = True
            suspicious.notified_at = timezone.now()
            suspicious.save()
        except Exception:
            pass


def check_account_locked(user) -> Optional[AccountLockout]:
    """
    Check if a user account is locked.

    Args:
        user: The user to check

    Returns:
        Active AccountLockout instance if locked, None otherwise
    """
    return AccountLockout.objects.filter(
        user=user,
        is_active=True,
        locked_until__gt=timezone.now()
    ).first()
