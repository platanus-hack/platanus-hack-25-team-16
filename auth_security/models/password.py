"""
Password-related models.

Models for tracking password history and preventing password reuse.
"""

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class PasswordHistory(models.Model):
    """
    Store hashed passwords to prevent reuse.

    Only stores password hashes, never plaintext passwords.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_history',
        help_text=_("User whose password this was")
    )
    password_hash = models.CharField(
        max_length=255,
        help_text=_("Hashed password (same format as User.password)")
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("When this password was set")
    )

    class Meta:
        verbose_name = _("Password History")
        verbose_name_plural = _("Password Histories")
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self):
        return f"Password for {self.user.username} set at {self.created_at}"
