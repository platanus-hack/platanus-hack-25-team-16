from __future__ import annotations

import hmac
import hashlib
import os
from datetime import timedelta
from typing import Any, Dict, List

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from .base import canonical_json
from ..models import AuditLogEntry


class TamperEvidentPostgres:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.hash_chaining = cfg.get("AUDIT_LOG", {}).get("HASH_CHAINING", True)
        key_env = cfg.get("AUDIT_LOG", {}).get("HASH_KEY_ENV") or "AUDIT_HASH_KEY"
        key = os.environ.get(key_env) or getattr(settings, "SECRET_KEY", "")
        if not key:
            raise ImproperlyConfigured(
                "No se encontró clave HMAC para la cadena de hash de auditoría."
            )
        self.key = key.encode("utf-8")

    def _compute_hash(
        self, prev_hash: str, canonical_payload: str, timestamp: str
    ) -> str:
        content = f"{prev_hash}|{canonical_payload}|{timestamp}".encode("utf-8")
        return hmac.new(self.key, content, hashlib.sha256).hexdigest()

    def _canonical_payload(self, event: Dict[str, Any], timestamp: str) -> str:
        payload = {
            "app_label": event.get("app_label"),
            "model": event.get("model"),
            "pk": event.get("object_pk"),
            "action": event.get("action"),
            "snapshot": event.get("snapshot"),
            "metadata": event.get("metadata") or {},
            "timestamp": timestamp,
        }
        return canonical_json(payload)

    @transaction.atomic
    def append(self, event: Dict[str, Any]) -> None:
        if not self.cfg.get("AUDIT_LOG", {}).get("ENABLED", True):
            return

        timestamp = timezone.now()
        timestamp_str = timestamp.isoformat()

        # Preparar datos tal como se almacenarán
        app_label = event.get("app_label")
        model = event.get("model")
        object_pk = str(event.get("object_pk"))
        action = event.get("action")
        snapshot = event.get("snapshot") or {}
        metadata = event.get("metadata") or {}

        # Normalize snapshot and metadata through JSON serialization/deserialization
        # to ensure they match what will be read back from JSONField
        import json

        snapshot = json.loads(json.dumps(snapshot))
        metadata = json.loads(json.dumps(metadata))

        # Calcular canonical payload con los datos exactos que se almacenarán
        canonical_payload = self._canonical_payload(  # noqa: F841
            {
                "app_label": app_label,
                "model": model,
                "object_pk": object_pk,
                "action": action,
                "snapshot": snapshot,
                "metadata": metadata,
            },
            timestamp_str,
        )

        # Obtener hash anterior
        hash_prev = ""
        if self.hash_chaining:
            latest = (
                AuditLogEntry.objects.select_for_update()
                .order_by("-id")
                .only("id", "hash_current")
                .first()
            )
            hash_prev = latest.hash_current if latest else ""

        # Crear entrada con todos los datos (sin hash aún)
        entry = AuditLogEntry(
            app_label=app_label,
            model=model,
            object_pk=object_pk,
            action=action,
            snapshot=snapshot,
            metadata=metadata,
            actor=event.get("actor"),
            actor_label=event.get("actor_label"),
            ip_address=event.get("ip_address"),
            user_agent=event.get("user_agent"),
            correlation_id=event.get("correlation_id"),
            request_path=event.get("request_path"),
            http_method=event.get("http_method"),
            body=event.get("body"),
            hash_prev=hash_prev,
            hash_current="",  # Temporal
            timestamp=timestamp,
        )
        entry.save()

        # Recalcular hash con el timestamp exacto que se guardó en la DB
        entry.refresh_from_db()
        timestamp_str_from_db = entry.timestamp.isoformat()
        canonical_payload_final = self._canonical_payload(
            {
                "app_label": app_label,
                "model": model,
                "object_pk": object_pk,
                "action": action,
                "snapshot": snapshot,
                "metadata": metadata,
            },
            timestamp_str_from_db,
        )
        hash_current_final = self._compute_hash(
            hash_prev, canonical_payload_final, timestamp_str_from_db
        )
        entry.hash_current = hash_current_final
        entry.save(update_fields=["hash_current"])

    def verify_chain(self) -> Dict[str, Any]:
        mismatches: List[int] = []
        expected_prev = ""
        checked = 0

        qs = AuditLogEntry.objects.order_by("id").iterator()
        for entry in qs:
            canonical = self._canonical_payload(
                {
                    "app_label": entry.app_label,
                    "model": entry.model,
                    "object_pk": entry.object_pk,
                    "action": entry.action,
                    "snapshot": entry.snapshot,
                    "metadata": entry.metadata,
                },
                entry.timestamp.isoformat(),
            )
            expected = self._compute_hash(
                expected_prev, canonical, entry.timestamp.isoformat()
            )
            if entry.hash_current != expected:
                mismatches.append(entry.id)
            expected_prev = entry.hash_current
            checked += 1

        return {"ok": not mismatches, "checked": checked, "mismatches": mismatches}

    def prune(self, retention_days: int) -> int:
        cutoff = timezone.now() - timedelta(days=retention_days)
        deleted, _ = AuditLogEntry.objects.filter(timestamp__lt=cutoff).delete()
        return deleted

    @transaction.atomic
    def append_api_log(self, event: Dict[str, Any]) -> None:
        """
        Append an API request log entry with cryptographic integrity.
        """
        from auditory.api.models import APIRequestLog
        import json

        if not self.cfg.get("API_REQUEST_LOG", {}).get("ENABLED", True):
            return

        timestamp = timezone.now()
        timestamp_str = timestamp.isoformat()

        # Normalize data through JSON serialization to match what will be read from JSONField
        query_params = json.loads(json.dumps(event.get("query_params", {})))
        response_headers = json.loads(json.dumps(event.get("response_headers", {})))
        permission_checks = json.loads(json.dumps(event.get("permission_checks", [])))
        validation_errors = json.loads(json.dumps(event.get("validation_errors", [])))

        # Prepare canonical payload for API log
        canonical_payload = canonical_json(
            {
                "correlation_id": event.get("correlation_id"),
                "endpoint": event.get("endpoint"),
                "http_method": event.get("http_method"),
                "request_path": event.get("request_path"),
                "response_status": event.get("response_status"),
                "user_id": event.get("user_id"),
                "ip_address": event.get("ip_address"),
                "timestamp": timestamp_str,
            }
        )

        # Get previous hash for chain integrity
        hash_prev = ""
        hash_current = ""
        if self.hash_chaining:
            latest = (
                APIRequestLog.objects.select_for_update()
                .order_by("-timestamp")
                .only("event_id", "hash_current")
                .first()
            )
            hash_prev = latest.hash_current if latest else "0" * 64
            hash_current = self._compute_hash(
                hash_prev, canonical_payload, timestamp_str
            )

        # Create API log entry with all data
        entry = APIRequestLog(
            timestamp=timestamp,
            correlation_id=event.get("correlation_id", ""),
            endpoint=event.get("endpoint", ""),
            http_method=event.get("http_method", ""),
            request_path=event.get("request_path", ""),
            content_type=event.get("content_type"),
            accept=event.get("accept"),
            referer=event.get("referer"),
            origin=event.get("origin"),
            request_body_hash=event.get("request_body_hash"),
            request_size=event.get("request_size", 0),
            query_params=query_params,
            response_status=event.get("response_status", 0),
            response_time_ms=event.get("response_time_ms", 0),
            response_body_hash=event.get("response_body_hash"),
            response_size=event.get("response_size", 0),
            response_headers=response_headers,
            user_id=event.get("user_id"),
            username=event.get("username"),
            session_id=event.get("session_id"),
            ip_address=event.get("ip_address", ""),
            user_agent=event.get("user_agent", ""),
            auth_method=event.get("auth_method"),
            auth_success=event.get("auth_success", True),
            permission_checks=permission_checks,
            throttled=event.get("throttled", False),
            rate_limit_remaining=event.get("rate_limit_remaining"),
            validation_errors=validation_errors,
            error_message=event.get("error_message"),
            traceback_hash=event.get("traceback_hash"),
            api_version=event.get("api_version"),
            api_type=event.get("api_type", "rest"),
            resource_type=event.get("resource_type"),
            resource_id=event.get("resource_id"),
            hash_prev=hash_prev,
            hash_current=hash_current or "0" * 64,
        )
        entry.save()

    def verify_api_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the API request log chain.
        """
        from auditory.api.models import APIRequestLog

        mismatches: List[str] = []
        expected_prev = "0" * 64
        checked = 0

        qs = APIRequestLog.objects.order_by("timestamp").iterator()
        for entry in qs:
            if self.hash_chaining:
                canonical = canonical_json(
                    {
                        "correlation_id": entry.correlation_id,
                        "endpoint": entry.endpoint,
                        "http_method": entry.http_method,
                        "request_path": entry.request_path,
                        "response_status": entry.response_status,
                        "user_id": entry.user_id,
                        "ip_address": entry.ip_address,
                        "timestamp": entry.timestamp.isoformat(),
                    }
                )
                expected = self._compute_hash(
                    expected_prev, canonical, entry.timestamp.isoformat()
                )
                if entry.hash_current != expected:
                    mismatches.append(str(entry.event_id))
                expected_prev = entry.hash_current
            checked += 1

        return {"ok": not mismatches, "checked": checked, "mismatches": mismatches}

    def prune_api_logs(self, retention_days: int) -> int:
        """
        Prune old API request logs based on retention policy.
        """
        from auditory.api.models import APIRequestLog

        cutoff = timezone.now() - timedelta(days=retention_days)
        deleted, _ = APIRequestLog.objects.filter(timestamp__lt=cutoff).delete()
        return deleted
