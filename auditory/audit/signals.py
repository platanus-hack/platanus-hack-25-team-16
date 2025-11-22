from __future__ import annotations

from functools import partial
from typing import Any, Dict, Iterable

from django.apps import apps
from django.forms.models import model_to_dict
from django.db.models.signals import post_delete, post_save

from .context import audit_context


def _serialize_instance(instance) -> Dict[str, Any]:
    from decimal import Decimal
    from datetime import datetime, date

    try:
        data = model_to_dict(instance)
    except Exception:
        data = {}

    # Convertir tipos no-JSON-serializables
    def convert_value(obj):
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {k: convert_value(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [convert_value(v) for v in obj]
        return obj

    data = convert_value(data)
    data["_repr"] = str(instance)
    return data


def _build_event(sender, instance, action: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "app_label": instance._meta.app_label,
        "model": instance._meta.model_name,
        "object_pk": instance.pk,
        "action": action,
        "snapshot": _serialize_instance(instance),
        "metadata": {"signal": action},
        "actor": ctx.get("actor"),
        "actor_label": ctx.get("actor_label"),
        "ip_address": ctx.get("ip_address"),
        "user_agent": ctx.get("user_agent"),
        "correlation_id": ctx.get("correlation_id"),
        "request_path": ctx.get("request_path"),
        "http_method": ctx.get("http_method"),
        "body": ctx.get("body"),
    }


def _handle_save(backend, sender, instance, created, **kwargs):
    if kwargs.get("raw"):
        return
    ctx = audit_context.get().copy()
    action = "create" if created else "update"
    event = _build_event(sender, instance, action, ctx)
    backend.append(event)


def _handle_delete(backend, sender, instance, **kwargs):
    ctx = audit_context.get().copy()
    event = _build_event(sender, instance, "delete", ctx)
    backend.append(event)


def _should_audit_model(model_class, audit_cfg: Dict[str, Any]) -> bool:
    """
    Determina si un modelo debe ser auditado basándose en la configuración.

    Lógica:
    1. Si hay lista de MODELS (whitelist), solo auditar esos modelos
    2. Si MODELS está vacío, auditar todos EXCEPTO los de MODELS_BLACKLIST
    3. Siempre excluir AuditLogEntry para evitar recursión infinita
    """
    app_label = model_class._meta.app_label
    model_name = model_class._meta.model_name
    dotted = f"{app_label}.{model_name}"

    if model_name == "auditlogentry" and app_label == "auditory":
        return False

    whitelist = audit_cfg.get("MODELS", [])
    blacklist = audit_cfg.get("MODELS_BLACKLIST", [])

    whitelist_normalized = [m.lower() for m in whitelist]
    blacklist_normalized = [m.lower() for m in blacklist]
    dotted_lower = dotted.lower()

    if whitelist:
        return dotted_lower in whitelist_normalized

    return dotted_lower not in blacklist_normalized


def register_signals(cfg: Dict[str, Any], backend, policy=None) -> None:
    audit_cfg = cfg.get("AUDIT_LOG", {})
    if not audit_cfg.get("ENABLED", True):
        return

    # Obtener whitelist explícita
    model_paths: Iterable[str] = audit_cfg.get("MODELS", [])

    if model_paths:
        for dotted in model_paths:
            try:
                model_class = apps.get_model(dotted)
            except (LookupError, ValueError):
                continue

            if _should_audit_model(model_class, audit_cfg):
                post_save.connect(partial(_handle_save, backend), sender=model_class, weak=False)
                post_delete.connect(partial(_handle_delete, backend), sender=model_class, weak=False)
    else:
        for model_class in apps.get_models():
            if _should_audit_model(model_class, audit_cfg):
                post_save.connect(partial(_handle_save, backend), sender=model_class, weak=False)
                post_delete.connect(partial(_handle_delete, backend), sender=model_class, weak=False)
