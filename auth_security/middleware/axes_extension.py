"""
Extension to django-axes for additional security features.

Adds suspicious login detection, notifications, and custom behaviors
on top of django-axes base functionality.
"""

from datetime import timedelta
from typing import Any

from django.contrib.auth.signals import user_logged_in
from django.core.mail import send_mail
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext as _

from ..conf import get_setting
from ..models import SuspiciousLogin
from ..signals import suspicious_login_detected
from ..utils.ip import get_client_ip


@receiver(user_logged_in)
def check_suspicious_login(sender, request, user, **kwargs):
    """
    Check if login is suspicious and flag it.

    This is triggered after successful login (axes has already done brute force check).
    We add additional checks for suspicious patterns.
    """
    auth_config = get_setting("AUTH_PROTECTION", {})
    notification_config = auth_config.get("NOTIFICATION", {})

    if not notification_config.get("EMAIL_ON_SUSPICIOUS_LOGIN", True):
        return

    ip_address = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")

    suspicious_reasons: list[tuple[str, dict[str, Any]]] = []

    # Check for new IP address
    if _is_new_ip(user, ip_address):
        suspicious_reasons.append(("new_ip", {"ip": ip_address}))

    # Check for unusual user agent
    if _is_unusual_user_agent(user, user_agent):
        suspicious_reasons.append(("unusual_agent", {"user_agent": user_agent[:200]}))

    # Check for velocity (multiple logins in short time)
    if _check_velocity(user):
        suspicious_reasons.append(("velocity", {}))

    # If suspicious, create records and notify
    for reason, details in suspicious_reasons:
        suspicious = SuspiciousLogin.objects.create(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            reason=reason,
            details=details,
        )

        # Send signal
        suspicious_login_detected.send(
            sender=check_suspicious_login,
            suspicious_login=suspicious,
            request=request,
        )

        # Send notification
        _send_suspicious_login_notification(user, suspicious)


def _is_new_ip(user, ip_address: str) -> bool:
    """Check if this is a new IP address for the user."""
    # Try to use axes history first
    try:
        from axes.models import AccessAttempt

        previous_success = AccessAttempt.objects.filter(
            username=user.username,
            ip_address=ip_address,
            failures_since_start=0,  # Successful login
        ).exists()

        return not previous_success
    except Exception:
        # Fallback: check our suspicious login history
        previous = SuspiciousLogin.objects.filter(
            user=user,
            ip_address=ip_address,
        ).exists()

        return not previous


def _is_unusual_user_agent(user, user_agent: str) -> bool:
    """
    Check if user agent is unusual for this user.

    This is a simple check - in production you'd want more sophisticated analysis.
    """
    if not user_agent:
        return True

    # If we haven't seen it before, it might be suspicious
    # But we'll be lenient here - only flag truly unusual patterns
    suspicious_patterns = [
        "curl",
        "wget",
        "python-requests",
        "scrapy",
        "bot",
        "crawler",
        "spider",
    ]

    ua_lower = user_agent.lower()
    return any(pattern in ua_lower for pattern in suspicious_patterns)


def _check_velocity(user: Any) -> bool:
    """
    Check for high velocity logins (multiple logins in short time).

    This could indicate credential stuffing or account sharing.
    """

    # Check if user has logged in more than 5 times in the last 10 minutes
    threshold_time = timezone.now() - timedelta(minutes=10)

    recent_logins = SuspiciousLogin.objects.filter(
        user=user,
        timestamp__gte=threshold_time,
    ).count()

    # Also check axes attempts
    try:
        from axes.models import AccessAttempt

        recent_axes = AccessAttempt.objects.filter(
            username=user.username,
            attempt_time__gte=threshold_time,
            failures_since_start=0,  # Successful
        ).count()

        recent_logins += recent_axes
    except Exception:
        pass

    return recent_logins > 5


def _send_suspicious_login_notification(user, suspicious: SuspiciousLogin):
    """Send email notification about suspicious login."""
    if not user.email:
        return

    subject = _("Security Alert: Unusual login to your account")
    message = _(
        f"Hello {user.username},\n\n"
        f"We detected a login to your account that looks unusual.\n\n"
        f"Time: {suspicious.timestamp}\n"
        f"IP Address: {suspicious.ip_address}\n"
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
