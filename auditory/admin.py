from django.contrib import admin
from django.utils.html import format_html
import json

from .audit.models import AuditLogEntry
from .api.models import APIRequestLog
from django.utils import timezone
from datetime import timedelta


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    """
    Admin interface for AuditLogEntry model.
    Provides read-only access to audit logs with filtering and search capabilities.
    """

    list_display = [
        "id",
        "timestamp",
        "action_badge",
        "model_info",
        "object_pk",
        "actor_info",
        "ip_address",
        "correlation_id_short",
        "hash_status",
    ]
    list_filter = [
        "action",
        "app_label",
        "model",
        "timestamp",
        "http_method",
    ]
    search_fields = [
        "app_label",
        "model",
        "object_pk",
        "actor",
        "actor_label",
        "ip_address",
        "correlation_id",
        "request_path",
    ]
    readonly_fields = [
        "timestamp",
        "app_label",
        "model",
        "object_pk",
        "action",
        "snapshot_formatted",
        "metadata_formatted",
        "actor",
        "actor_label",
        "ip_address",
        "user_agent",
        "correlation_id",
        "request_path",
        "http_method",
        "body_formatted",
        "hash_prev",
        "hash_current",
        "hash_status",
    ]
    date_hierarchy = "timestamp"
    ordering = ["-timestamp"]
    list_per_page = 50

    fieldsets = (
        (
            "Event Information",
            {
                "fields": (
                    "timestamp",
                    "action",
                    "app_label",
                    "model",
                    "object_pk",
                )
            },
        ),
        (
            "Actor Information",
            {
                "fields": (
                    "actor",
                    "actor_label",
                    "ip_address",
                    "user_agent",
                )
            },
        ),
        (
            "Request Information",
            {
                "fields": (
                    "correlation_id",
                    "request_path",
                    "http_method",
                    "body_formatted",
                )
            },
        ),
        (
            "Data",
            {
                "fields": (
                    "snapshot_formatted",
                    "metadata_formatted",
                )
            },
        ),
        (
            "Integrity",
            {
                "fields": (
                    "hash_prev",
                    "hash_current",
                    "hash_status",
                ),
                "description": "Hash chain information for tamper detection",
            },
        ),
    )

    def action_badge(self, obj):
        """Display action with color-coded badge"""
        colors = {
            "create": "green",
            "update": "blue",
            "delete": "red",
        }
        color = colors.get(obj.action, "gray")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px; font-weight: bold;">{}</span>',
            color,
            obj.action.upper(),
        )

    action_badge.short_description = "Action"

    def model_info(self, obj):
        """Display app_label.model in a readable format"""
        return format_html(
            "<strong>{}</strong>.<code>{}</code>",
            obj.app_label,
            obj.model,
        )

    model_info.short_description = "Model"

    def actor_info(self, obj):
        """Display actor information"""
        if obj.actor:
            return format_html(
                "<strong>{}</strong><br><small>{}</small>",
                obj.actor_label or obj.actor,
                obj.actor,
            )
        return format_html('<span style="color: #999;">Anonymous</span>')

    actor_info.short_description = "Actor"

    def correlation_id_short(self, obj):
        """Display shortened correlation ID"""
        if obj.correlation_id:
            return format_html(
                '<code title="{}">{}</code>',
                obj.correlation_id,
                obj.correlation_id[:8] + "..."
                if len(obj.correlation_id) > 8
                else obj.correlation_id,
            )
        return "-"

    correlation_id_short.short_description = "Correlation ID"

    def hash_status(self, obj):
        """Display hash chain status"""
        if obj.hash_current:
            return format_html(
                '<span style="color: green;" title="Hash: {}">✓ Valid</span>',
                obj.hash_current[:16] + "...",
            )
        return format_html('<span style="color: #999;">-</span>')

    hash_status.short_description = "Hash Status"

    def snapshot_formatted(self, obj):
        """Display formatted snapshot JSON"""
        if obj.snapshot:
            formatted = json.dumps(obj.snapshot, indent=2, ensure_ascii=False)
            return format_html(
                '<pre style="max-height: 300px; overflow: auto;">{}</pre>', formatted
            )
        return "-"

    snapshot_formatted.short_description = "Snapshot"

    def metadata_formatted(self, obj):
        """Display formatted metadata JSON"""
        if obj.metadata:
            formatted = json.dumps(obj.metadata, indent=2, ensure_ascii=False)
            return format_html(
                '<pre style="max-height: 200px; overflow: auto;">{}</pre>', formatted
            )
        return "-"

    metadata_formatted.short_description = "Metadata"

    def body_formatted(self, obj):
        """Display formatted body JSON"""
        if obj.body:
            formatted = json.dumps(obj.body, indent=2, ensure_ascii=False)
            return format_html(
                '<pre style="max-height: 200px; overflow: auto;">{}</pre>', formatted
            )
        return "-"

    body_formatted.short_description = "Request Body"

    def has_add_permission(self, request):
        """Disable adding new audit log entries manually"""
        return False

    def has_change_permission(self, request, obj=None):
        """Disable editing audit log entries (they are immutable)"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Disable deleting audit log entries (they are immutable)"""
        return False

    class Media:
        css = {"all": ("admin/css/audit_log_admin.css",)}


@admin.register(APIRequestLog)
class APIRequestLogAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing and managing API request logs.
    """

    # List display configuration
    list_display = [
        "timestamp",
        "http_method",
        "endpoint",
        "response_status",
        "response_time_ms",
        "username",
        "ip_address",
    ]

    # Filters
    list_filter = [
        "http_method",
        "response_status",
        "auth_method",
        "auth_success",
        "throttled",
        "api_type",
        ("timestamp", admin.DateFieldListFilter),
    ]

    # Search
    search_fields = [
        "correlation_id",
        "endpoint",
        "request_path",
        "username",
        "ip_address",
        "user_agent",
        "error_message",
    ]

    # Readonly fields (logs should not be edited)
    readonly_fields = [
        "event_id",
        "timestamp",
        "correlation_id",
        "endpoint",
        "http_method",
        "request_path",
        "content_type",
        "accept",
        "referer",
        "origin",
        "request_body_hash",
        "request_size",
        "query_params",
        "response_status",
        "response_time_ms",
        "response_body_hash",
        "response_size",
        "response_headers",
        "user_id",
        "username",
        "session_id",
        "ip_address",
        "user_agent",
        "auth_method",
        "auth_success",
        "permission_checks",
        "throttled",
        "rate_limit_remaining",
        "validation_errors",
        "error_message",
        "traceback_hash",
        "api_version",
        "api_type",
        "resource_type",
        "resource_id",
        "hash_prev",
        "hash_current",
    ]

    # Ordering
    ordering = ["-timestamp"]

    # Pagination
    list_per_page = 50

    # Date hierarchy
    date_hierarchy = "timestamp"

    # Fieldsets for detail view
    fieldsets = (
        (
            "Request Information",
            {
                "fields": (
                    "event_id",
                    "timestamp",
                    "correlation_id",
                    "endpoint",
                    "http_method",
                    "request_path",
                )
            },
        ),
        (
            "Request Headers",
            {
                "fields": (
                    "content_type",
                    "accept",
                    "referer",
                    "origin",
                    "user_agent",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Request Body",
            {
                "fields": (
                    "request_body_hash",
                    "request_size",
                    "query_params",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Response Information",
            {
                "fields": (
                    "response_status",
                    "response_time_ms",
                    "response_size",
                    "response_body_hash",
                    "response_headers",
                )
            },
        ),
        (
            "User & Session",
            {
                "fields": (
                    "user_id",
                    "username",
                    "session_id",
                    "ip_address",
                    "auth_method",
                    "auth_success",
                )
            },
        ),
        (
            "Security & Permissions",
            {
                "fields": (
                    "permission_checks",
                    "throttled",
                    "rate_limit_remaining",
                    "validation_errors",
                    "error_message",
                    "traceback_hash",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "API Metadata",
            {
                "fields": (
                    "api_version",
                    "api_type",
                    "resource_type",
                    "resource_id",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Cryptographic Integrity",
            {
                "fields": (
                    "hash_current",
                    "hash_prev",
                ),
                "classes": ("collapse",),
            },
        ),
    )

    def has_add_permission(self, request):
        """Prevent adding logs manually."""
        return False

    def has_change_permission(self, request, obj=None):
        """Allow viewing but prevent editing logs."""
        if obj is None:
            # Allow viewing the changelist
            return request.user.is_authenticated
        # For detail view, allow viewing but Django will prevent editing due to readonly_fields
        return request.user.is_authenticated

    def has_delete_permission(self, request, obj=None):
        """Only superusers can delete logs."""
        return request.user.is_superuser

    # Override changelist view to add statistics
    def changelist_view(self, request, extra_context=None):
        """Add statistics to the changelist view."""
        extra_context = extra_context or {}

        # Calculate statistics for last 24 hours
        last_24h = timezone.now() - timedelta(hours=24)
        recent_logs = APIRequestLog.objects.filter(timestamp__gte=last_24h)

        if recent_logs.exists():
            from django.db.models import Avg, Count

            stats = recent_logs.aggregate(
                total=Count("event_id"),
                avg_response_time=Avg("response_time_ms"),
            )

            status_dist = (
                recent_logs.values("response_status")
                .annotate(count=Count("response_status"))
                .order_by("-count")[:5]
            )

            extra_context.update(
                {
                    "stats": {
                        "total_24h": stats["total"],
                        "avg_response_time": round(stats["avg_response_time"] or 0, 2),
                        "status_distribution": status_dist,
                        "error_rate": recent_logs.filter(
                            response_status__gte=400
                        ).count()
                        / stats["total"]
                        * 100
                        if stats["total"] > 0
                        else 0,
                    }
                }
            )

        return super().changelist_view(request, extra_context=extra_context)
