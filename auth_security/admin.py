"""Admin interface for auth_security models."""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import (
    PasswordHistory,
    SuspiciousLogin,
)


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    """Admin interface for PasswordHistory model."""

    list_display = [
        'user',
        'created_at',
    ]
    list_filter = [
        'created_at',
    ]
    search_fields = [
        'user__username',
        'user__email',
    ]
    readonly_fields = [
        'user',
        'password_hash',
        'created_at',
    ]
    date_hierarchy = 'created_at'

    def has_add_permission(self, request):
        """Disable manual creation."""
        return False


@admin.register(SuspiciousLogin)
class SuspiciousLoginAdmin(admin.ModelAdmin):
    """Admin interface for SuspiciousLogin model."""

    list_display = [
        'timestamp',
        'user',
        'ip_address',
        'reason',
        'notified_badge',
        'reviewed_badge',
    ]
    list_filter = [
        'reason',
        'notified',
        'reviewed',
        'timestamp',
    ]
    search_fields = [
        'user__username',
        'user__email',
        'ip_address',
    ]
    readonly_fields = [
        'user',
        'axes_attempt_id',
        'ip_address',
        'user_agent',
        'timestamp',
        'reason',
        'details',
        'notified',
        'notified_at',
    ]
    fieldsets = (
        (_('Login Information'), {
            'fields': ('user', 'axes_attempt_id', 'ip_address', 'user_agent', 'timestamp', 'reason', 'details')
        }),
        (_('Notification'), {
            'fields': ('notified', 'notified_at')
        }),
        (_('Review'), {
            'fields': ('reviewed', 'reviewed_at', 'reviewed_by')
        }),
    )
    date_hierarchy = 'timestamp'

    def notified_badge(self, obj):
        """Display notification status."""
        if obj.notified:
            return format_html('<span style="color: green;">✓</span>')
        return format_html('<span style="color: red;">✗</span>')
    notified_badge.short_description = _('Notified')

    def reviewed_badge(self, obj):
        """Display review status."""
        if obj.reviewed:
            return format_html('<span style="color: green;">✓</span>')
        return format_html('<span style="color: red;">✗</span>')
    reviewed_badge.short_description = _('Reviewed')

    def has_add_permission(self, request):
        """Disable manual creation."""
        return False


# Note: For other security-related admin interfaces:
# - Login attempts: /admin/axes/accessattempt/ (django-axes)
# - Account lockouts: /admin/axes/accessfailurelog/ (django-axes)
# - MFA devices: /admin/otp_totp/totpdevice/ (django-otp)
# - Static tokens: /admin/otp_static/staticdevice/ (django-otp)
