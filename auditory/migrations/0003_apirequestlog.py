# Generated manually for APIRequestLog model

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("auditory", "0002_add_api_request_log"),
    ]

    operations = [
        migrations.CreateModel(
            name="APIRequestLog",
            fields=[
                (
                    "event_id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("timestamp", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "correlation_id",
                    models.CharField(
                        db_index=True,
                        help_text="Unique ID for request tracing across services",
                        max_length=64,
                    ),
                ),
                (
                    "endpoint",
                    models.CharField(
                        db_index=True,
                        help_text="Normalized endpoint path (e.g., /api/v1/expenses/{id}/)",
                        max_length=255,
                    ),
                ),
                (
                    "http_method",
                    models.CharField(
                        choices=[
                            ("GET", "GET"),
                            ("POST", "POST"),
                            ("PUT", "PUT"),
                            ("PATCH", "PATCH"),
                            ("DELETE", "DELETE"),
                            ("HEAD", "HEAD"),
                            ("OPTIONS", "OPTIONS"),
                        ],
                        max_length=10,
                    ),
                ),
                (
                    "request_path",
                    models.TextField(help_text="Full path including query parameters"),
                ),
                (
                    "content_type",
                    models.CharField(blank=True, max_length=100, null=True),
                ),
                ("accept", models.CharField(blank=True, max_length=100, null=True)),
                ("referer", models.TextField(blank=True, null=True)),
                ("origin", models.CharField(blank=True, max_length=255, null=True)),
                (
                    "request_body_hash",
                    models.CharField(
                        blank=True,
                        help_text="SHA256 hash of request body for integrity",
                        max_length=64,
                        null=True,
                    ),
                ),
                (
                    "request_size",
                    models.IntegerField(default=0, help_text="Request size in bytes"),
                ),
                (
                    "query_params",
                    models.JSONField(
                        blank=True, default=dict, help_text="Sanitized query parameters"
                    ),
                ),
                (
                    "response_status",
                    models.IntegerField(help_text="HTTP response status code"),
                ),
                (
                    "response_time_ms",
                    models.IntegerField(help_text="Response latency in milliseconds"),
                ),
                (
                    "response_body_hash",
                    models.CharField(
                        blank=True,
                        help_text="SHA256 hash of response body (errors only)",
                        max_length=64,
                        null=True,
                    ),
                ),
                (
                    "response_size",
                    models.IntegerField(default=0, help_text="Response size in bytes"),
                ),
                (
                    "response_headers",
                    models.JSONField(
                        blank=True, default=dict, help_text="Selected response headers"
                    ),
                ),
                ("user_id", models.IntegerField(blank=True, db_index=True, null=True)),
                ("username", models.CharField(blank=True, max_length=150, null=True)),
                ("session_id", models.CharField(blank=True, max_length=64, null=True)),
                ("ip_address", models.GenericIPAddressField()),
                ("user_agent", models.TextField()),
                (
                    "auth_method",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("session", "Session"),
                            ("jwt", "JWT Token"),
                            ("apikey", "API Key"),
                            ("oauth2", "OAuth2"),
                            ("basic", "Basic Auth"),
                            (None, "Anonymous"),
                        ],
                        max_length=50,
                        null=True,
                    ),
                ),
                ("auth_success", models.BooleanField(default=True)),
                (
                    "permission_checks",
                    models.JSONField(
                        default=list,
                        help_text="List of permissions verified during request",
                    ),
                ),
                ("throttled", models.BooleanField(default=False)),
                ("rate_limit_remaining", models.IntegerField(blank=True, null=True)),
                ("validation_errors", models.JSONField(blank=True, default=list)),
                ("error_message", models.TextField(blank=True, null=True)),
                (
                    "traceback_hash",
                    models.CharField(
                        blank=True,
                        help_text="Hash of traceback for error grouping",
                        max_length=64,
                        null=True,
                    ),
                ),
                (
                    "api_version",
                    models.CharField(
                        blank=True,
                        help_text="API version (e.g., v1, v2)",
                        max_length=10,
                        null=True,
                    ),
                ),
                (
                    "api_type",
                    models.CharField(
                        choices=[
                            ("rest", "REST API"),
                            ("graphql", "GraphQL"),
                            ("websocket", "WebSocket"),
                            ("rpc", "RPC"),
                        ],
                        default="rest",
                        max_length=20,
                    ),
                ),
                (
                    "resource_type",
                    models.CharField(
                        blank=True,
                        help_text="Resource being accessed (e.g., expense, user)",
                        max_length=50,
                        null=True,
                    ),
                ),
                (
                    "resource_id",
                    models.CharField(
                        blank=True,
                        help_text="ID of specific resource",
                        max_length=64,
                        null=True,
                    ),
                ),
                (
                    "hash_prev",
                    models.CharField(
                        blank=True,
                        help_text="Hash of previous log entry",
                        max_length=128,
                        null=True,
                    ),
                ),
                (
                    "hash_current",
                    models.CharField(
                        db_index=True,
                        help_text="Hash of current entry for chain integrity",
                        max_length=128,
                    ),
                ),
            ],
            options={
                "verbose_name": "API Request Log",
                "verbose_name_plural": "API Request Logs",
                "db_table": "auditory_api_request_log",
                "ordering": ["-timestamp"],
            },
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(
                fields=["timestamp", "endpoint"], name="idx_api_log_time_endpoint"
            ),
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(
                fields=["user_id", "timestamp"], name="idx_api_log_user_time"
            ),
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(
                fields=["response_status", "timestamp"], name="idx_api_log_status_time"
            ),
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(
                fields=["correlation_id"], name="idx_api_log_correlation"
            ),
        ),
        migrations.AddIndex(
            model_name="apirequestlog",
            index=models.Index(fields=["hash_current"], name="idx_api_log_hash"),
        ),
    ]
