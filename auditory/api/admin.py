"""
Admin interface for API Request Logs.
"""

from django.contrib import admin
from django.utils import timezone
from django.utils.html import format_html
from datetime import timedelta
import json

from .models import APIRequestLog


@admin.register(APIRequestLog)
class APIRequestLogAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing and managing API request logs.
    """

    # List display configuration
    list_display = [
        'timestamp',
        'http_method_badge',
        'endpoint',
        'status_badge',
        'response_time_ms',
        'username',
        'ip_address',
    ]

    # Filters
    list_filter = [
        'http_method',
        'response_status',
        'auth_method',
        'auth_success',
        'throttled',
        'api_type',
        ('timestamp', admin.DateFieldListFilter),
    ]

    # Search
    search_fields = [
        'correlation_id',
        'endpoint',
        'request_path',
        'username',
        'ip_address',
        'user_agent',
        'error_message',
    ]

    # Readonly fields (logs should not be edited)
    readonly_fields = [
        'event_id',
        'timestamp',
        'correlation_id',
        'endpoint',
        'http_method',
        'request_path',
        'content_type',
        'accept',
        'referer',
        'origin',
        'request_body_hash',
        'request_size',
        'formatted_query_params',
        'response_status',
        'response_time_ms',
        'response_body_hash',
        'response_size',
        'formatted_response_headers',
        'user_id',
        'username',
        'session_id',
        'ip_address',
        'user_agent',
        'auth_method',
        'auth_success',
        'formatted_permission_checks',
        'throttled',
        'rate_limit_remaining',
        'formatted_validation_errors',
        'error_message',
        'traceback_hash',
        'api_version',
        'api_type',
        'resource_type',
        'resource_id',
        'hash_prev',
        'hash_current',
    ]

    # Ordering
    ordering = ['-timestamp']

    # Pagination
    list_per_page = 50

    # Date hierarchy
    date_hierarchy = 'timestamp'

    # Fieldsets for detail view
    fieldsets = (
        ('Request Information', {
            'fields': (
                'event_id',
                'timestamp',
                'correlation_id',
                'endpoint',
                'http_method',
                'request_path',
            )
        }),
        ('Request Headers', {
            'fields': (
                'content_type',
                'accept',
                'referer',
                'origin',
                'user_agent',
            ),
            'classes': ('collapse',),
        }),
        ('Request Body', {
            'fields': (
                'request_body_hash',
                'request_size',
                'formatted_query_params',
            ),
            'classes': ('collapse',),
        }),
        ('Response Information', {
            'fields': (
                'response_status',
                'response_time_ms',
                'response_size',
                'response_body_hash',
                'formatted_response_headers',
            )
        }),
        ('User & Session', {
            'fields': (
                'user_id',
                'username',
                'session_id',
                'ip_address',
                'auth_method',
                'auth_success',
            )
        }),
        ('Security & Permissions', {
            'fields': (
                'formatted_permission_checks',
                'throttled',
                'rate_limit_remaining',
                'formatted_validation_errors',
                'error_message',
                'traceback_hash',
            ),
            'classes': ('collapse',),
        }),
        ('API Metadata', {
            'fields': (
                'api_version',
                'api_type',
                'resource_type',
                'resource_id',
            ),
            'classes': ('collapse',),
        }),
        ('Cryptographic Integrity', {
            'fields': (
                'hash_current',
                'hash_prev',
            ),
            'classes': ('collapse',),
        }),
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

    # Custom display methods
    def http_method_badge(self, obj):
        """Display HTTP method with color badge."""
        colors = {
            'GET': '#28a745',
            'POST': '#007bff',
            'PUT': '#ffc107',
            'PATCH': '#17a2b8',
            'DELETE': '#dc3545',
            'HEAD': '#6c757d',
            'OPTIONS': '#6c757d',
        }
        color = colors.get(obj.http_method, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            obj.http_method
        )
    http_method_badge.short_description = 'Method'

    def status_badge(self, obj):
        """Display response status with color badge."""
        if obj.is_success:
            color = '#28a745'
        elif obj.is_client_error:
            color = '#ffc107'
        elif obj.is_server_error:
            color = '#dc3545'
        else:
            color = '#6c757d'

        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            obj.response_status
        )
    status_badge.short_description = 'Status'

    def formatted_query_params(self, obj):
        """Format query params as pretty JSON."""
        if not obj.query_params or obj.query_params == {}:
            return format_html('<em style="color: #999;">No query parameters</em>')
        return format_html(
            '<pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto;">{}</pre>',
            json.dumps(obj.query_params, indent=2)
        )
    formatted_query_params.short_description = 'Query Parameters'

    def formatted_response_headers(self, obj):
        """Format response headers as pretty JSON."""
        if not obj.response_headers or obj.response_headers == {}:
            return format_html('<em style="color: #999;">No response headers captured</em>')
        return format_html(
            '<pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto;">{}</pre>',
            json.dumps(obj.response_headers, indent=2)
        )
    formatted_response_headers.short_description = 'Response Headers'

    def formatted_permission_checks(self, obj):
        """Format permission checks as pretty JSON."""
        if not obj.permission_checks or obj.permission_checks == []:
            return format_html('<em style="color: #999;">No permission checks recorded</em>')
        return format_html(
            '<pre style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto;">{}</pre>',
            json.dumps(obj.permission_checks, indent=2)
        )
    formatted_permission_checks.short_description = 'Permission Checks'

    def formatted_validation_errors(self, obj):
        """Format validation errors as pretty JSON."""
        if not obj.validation_errors or obj.validation_errors == []:
            return format_html('<em style="color: #999;">No validation errors</em>')
        return format_html(
            '<pre style="background-color: #fff3cd; padding: 10px; border-radius: 4px; overflow-x: auto; border-left: 4px solid #ffc107;">{}</pre>',
            json.dumps(obj.validation_errors, indent=2)
        )
    formatted_validation_errors.short_description = 'Validation Errors'

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
                total=Count('event_id'),
                avg_response_time=Avg('response_time_ms'),
            )

            status_dist = recent_logs.values('response_status').annotate(
                count=Count('response_status')
            ).order_by('-count')[:5]

            extra_context.update({
                'stats': {
                    'total_24h': stats['total'],
                    'avg_response_time': round(stats['avg_response_time'] or 0, 2),
                    'status_distribution': status_dist,
                    'error_rate': recent_logs.filter(response_status__gte=400).count() / stats['total'] * 100 if stats['total'] > 0 else 0,
                }
            })

        return super().changelist_view(request, extra_context=extra_context)
