from django.db import models


class AuditLogEntry(models.Model):
    ACTION_CHOICES = (
        ("create", "create"),
        ("update", "update"),
        ("delete", "delete"),
    )

    timestamp = models.DateTimeField(auto_now_add=True)
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)
    object_pk = models.CharField(max_length=64)
    action = models.CharField(max_length=16, choices=ACTION_CHOICES)
    snapshot = models.JSONField(default=dict)
    metadata = models.JSONField(default=dict, blank=True)
    actor = models.CharField(max_length=128, blank=True, null=True)
    actor_label = models.CharField(max_length=128, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    correlation_id = models.CharField(max_length=64, blank=True, null=True)
    request_path = models.TextField(blank=True, null=True)
    http_method = models.CharField(max_length=8, blank=True, null=True)
    body = models.JSONField(blank=True, null=True)
    hash_prev = models.CharField(max_length=128, blank=True, null=True)
    hash_current = models.CharField(max_length=128, blank=True, null=True)

    class Meta:
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log Entries"
        indexes = [
            models.Index(fields=["app_label", "model", "object_pk"]),
            models.Index(fields=["timestamp"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        return f"{self.app_label}.{self.model}#{self.object_pk} {self.action}"
