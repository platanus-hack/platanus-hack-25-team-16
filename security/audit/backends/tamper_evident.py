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
            raise ImproperlyConfigured("No se encontró clave HMAC para la cadena de hash de auditoría.")
        self.key = key.encode("utf-8")

    def _compute_hash(self, prev_hash: str, canonical_payload: str, timestamp: str) -> str:
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
        canonical_payload = self._canonical_payload(event, timestamp_str)

        latest = None
        hash_prev = ""
        hash_current = ""
        if self.hash_chaining:
            latest = (
                AuditLogEntry.objects.select_for_update()
                .order_by("-id")
                .only("id", "hash_current")
                .first()
            )
            hash_prev = latest.hash_current if latest else ""
            hash_current = self._compute_hash(hash_prev, canonical_payload, timestamp_str)

        entry = AuditLogEntry(
            app_label=event.get("app_label"),
            model=event.get("model"),
            object_pk=str(event.get("object_pk")),
            action=event.get("action"),
            snapshot=event.get("snapshot") or {},
            metadata=event.get("metadata") or {},
            actor=event.get("actor"),
            actor_label=event.get("actor_label"),
            ip_address=event.get("ip_address"),
            user_agent=event.get("user_agent"),
            correlation_id=event.get("correlation_id"),
            request_path=event.get("request_path"),
            http_method=event.get("http_method"),
            body=event.get("body"),
            hash_prev=hash_prev,
            hash_current=hash_current,
            timestamp=timestamp,
        )
        entry.save()

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
            expected = self._compute_hash(expected_prev, canonical, entry.timestamp.isoformat())
            if entry.hash_current != expected:
                mismatches.append(entry.id)
            expected_prev = entry.hash_current
            checked += 1

        return {"ok": not mismatches, "checked": checked, "mismatches": mismatches}

    def prune(self, retention_days: int) -> int:
        cutoff = timezone.now() - timedelta(days=retention_days)
        deleted, _ = AuditLogEntry.objects.filter(timestamp__lt=cutoff).delete()
        return deleted
