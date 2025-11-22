"""
Suspicious activity tracking.

Extends django-axes with additional suspicious login detection and tracking.
"""

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class SuspiciousLogin(models.Model):
    """
    Track login attempts flagged as suspicious.

    This extends django-axes functionality by adding additional detection
    for suspicious patterns like new IPs, new geographic locations, etc.

    Links to axes.AccessAttempt for the actual login data.
    """

    REASON_CHOICES = [
        ("new_ip", _("New IP Address")),
        ("new_geo", _("New Geographic Location")),
        ("unusual_agent", _("Unusual User Agent")),
        ("impossible_travel", _("Impossible Travel")),
        ("velocity", _("High Velocity Logins")),
        ("other", _("Other")),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="suspicious_logins",
        help_text=_("User who logged in"),
    )
    # Reference to axes AccessAttempt if available
    axes_attempt_id = models.IntegerField(
        null=True, blank=True, help_text=_("Related axes AccessAttempt ID")
    )
    ip_address = models.GenericIPAddressField(
        default="0.0.0.0", help_text=_("IP address of suspicious login")
    )
    user_agent = models.TextField(blank=True, help_text=_("User agent string"))
    timestamp = models.DateTimeField(
        auto_now_add=True, db_index=True, help_text=_("When suspicious login occurred")
    )
    reason = models.CharField(
        max_length=20,
        choices=REASON_CHOICES,
        help_text=_("Why this login was flagged as suspicious"),
    )
    details = models.JSONField(
        null=True,
        blank=True,
        help_text=_("Additional details about why this was suspicious"),
    )
    notified = models.BooleanField(
        default=False, help_text=_("Whether user was notified about this login")
    )
    notified_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When user was notified")
    )
    reviewed = models.BooleanField(
        default=False, help_text=_("Whether this has been reviewed by security team")
    )
    reviewed_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When this was reviewed")
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_suspicious_logins",
        help_text=_("Who reviewed this login"),
    )

    class Meta:
        verbose_name = _("Suspicious Login")
        verbose_name_plural = _("Suspicious Logins")
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["-timestamp", "user"]),
            models.Index(fields=["reviewed", "-timestamp"]),
        ]

    def __str__(self):
        return f"Suspicious login: {self.user.username} - {self.get_reason_display()}"
