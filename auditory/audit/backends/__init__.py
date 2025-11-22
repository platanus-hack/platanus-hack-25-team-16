from typing import Any, Dict

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from .base import BaseAuditBackend

__all__ = ["BaseAuditBackend", "load_backend"]


def load_backend(cfg: Dict[str, Any]) -> BaseAuditBackend:
    backend_path = cfg.get("AUDIT_LOG", {}).get("STORAGE_BACKEND")
    if not backend_path:
        raise ImproperlyConfigured(
            "SECURITY_CONFIG.AUDIT_LOG.STORAGE_BACKEND no está definido."
        )
    try:
        backend_cls = import_string(backend_path)
    except Exception as exc:
        raise ImproperlyConfigured(
            f"No se pudo importar el backend {backend_path}"
        ) from exc
    return backend_cls(cfg)
