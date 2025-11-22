"""
Models for API request logging with cryptographic integrity.
ISO27001 compliant request tracking.
"""

import uuid
from django.db import models


class APIRequestLog(models.Model):
    """
    Comprehensive log of HTTP/API requests for ISO27001 compliance.
    Maintains cryptographic integrity through hash chain.
    """

    # === Event Identification ===
    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    # === Request Context (captured by AuditContextMiddleware) ===
    correlation_id = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Unique ID for request tracing across services"
    )

    # === Request Details ===
    endpoint = models.CharField(
        max_length=255,
        db_index=True,
        help_text="Normalized endpoint path (e.g., /api/v1/expenses/{id}/)"
    )
    http_method = models.CharField(
        max_length=10,
        choices=[
            ('GET', 'GET'),
            ('POST', 'POST'),
            ('PUT', 'PUT'),
            ('PATCH', 'PATCH'),
            ('DELETE', 'DELETE'),
            ('HEAD', 'HEAD'),
            ('OPTIONS', 'OPTIONS'),
        ]
    )
    request_path = models.TextField(help_text="Full path including query parameters")

    # Important headers (sanitized)
    content_type = models.CharField(max_length=100, null=True, blank=True)
    accept = models.CharField(max_length=100, null=True, blank=True)
    referer = models.TextField(null=True, blank=True)
    origin = models.CharField(max_length=255, null=True, blank=True)

    # Request body metadata
    request_body_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="SHA256 hash of request body for integrity"
    )
    request_size = models.IntegerField(default=0, help_text="Request size in bytes")
    query_params = models.JSONField(
        default=dict,
        blank=True,
        help_text="Sanitized query parameters"
    )

    # === Response Details ===
    response_status = models.IntegerField(help_text="HTTP response status code")
    response_time_ms = models.IntegerField(help_text="Response latency in milliseconds")
    response_body_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="SHA256 hash of response body (errors only)"
    )
    response_size = models.IntegerField(default=0, help_text="Response size in bytes")
    response_headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Selected response headers"
    )

    # === User Context ===
    user_id = models.IntegerField(null=True, blank=True, db_index=True)
    username = models.CharField(max_length=150, null=True, blank=True)
    session_id = models.CharField(max_length=64, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    # === Security Metrics ===
    auth_method = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        choices=[
            ('session', 'Session'),
            ('jwt', 'JWT Token'),
            ('apikey', 'API Key'),
            ('oauth2', 'OAuth2'),
            ('basic', 'Basic Auth'),
            (None, 'Anonymous'),
        ]
    )
    auth_success = models.BooleanField(default=True)
    permission_checks = models.JSONField(
        default=list,
        help_text="List of permissions verified during request"
    )
    throttled = models.BooleanField(default=False)
    rate_limit_remaining = models.IntegerField(null=True, blank=True)

    # === Errors and Validation ===
    validation_errors = models.JSONField(default=list, blank=True)
    error_message = models.TextField(null=True, blank=True)
    traceback_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Hash of traceback for error grouping"
    )

    # === API Metadata ===
    api_version = models.CharField(
        max_length=10,
        null=True,
        blank=True,
        help_text="API version (e.g., v1, v2)"
    )
    api_type = models.CharField(
        max_length=20,
        default='rest',
        choices=[
            ('rest', 'REST API'),
            ('graphql', 'GraphQL'),
            ('websocket', 'WebSocket'),
            ('rpc', 'RPC'),
        ]
    )
    resource_type = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        help_text="Resource being accessed (e.g., expense, user)"
    )
    resource_id = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="ID of specific resource"
    )

    # === Cryptographic Integrity (hash chain) ===
    hash_prev = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Hash of previous log entry"
    )
    hash_current = models.CharField(
        max_length=128,
        db_index=True,
        help_text="Hash of current entry for chain integrity"
    )

    class Meta:
        db_table = 'auditory_api_request_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'endpoint'], name='idx_api_log_time_endpoint'),
            models.Index(fields=['user_id', 'timestamp'], name='idx_api_log_user_time'),
            models.Index(fields=['response_status', 'timestamp'], name='idx_api_log_status_time'),
            models.Index(fields=['correlation_id'], name='idx_api_log_correlation'),
            models.Index(fields=['hash_current'], name='idx_api_log_hash'),
        ]
        verbose_name = 'API Request Log'
        verbose_name_plural = 'API Request Logs'

    def __str__(self):
        return f"{self.timestamp} - {self.http_method} {self.endpoint} - {self.response_status}"

    @property
    def is_success(self):
        """Check if request was successful (2xx status)."""
        return 200 <= self.response_status < 300

    @property
    def is_client_error(self):
        """Check if request had client error (4xx status)."""
        return 400 <= self.response_status < 500

    @property
    def is_server_error(self):
        """Check if request had server error (5xx status)."""
        return 500 <= self.response_status < 600

    @property
    def response_category(self):
        """Categorize response status."""
        if self.is_success:
            return 'success'
        elif self.is_client_error:
            return 'client_error'
        elif self.is_server_error:
            return 'server_error'
        else:
            return 'other'