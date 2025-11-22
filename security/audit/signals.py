from __future__ import annotations

from functools import partial
from typing import Any, Dict, Iterable

from django.apps import apps
from django.forms.models import model_to_dict
from django.db.models.signals import post_delete, post_save

from .context import audit_context


def _serialize_instance(instance) -> Dict[str, Any]:
    try:
        data = model_to_dict(instance)
    except Exception:
        data = {}
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


def register_signals(cfg: Dict[str, Any], backend, policy=None) -> None:
    audit_cfg = cfg.get("AUDIT_LOG", {})
    if not audit_cfg.get("ENABLED", True):
        return

    model_paths: Iterable[str] = audit_cfg.get("MODELS", [])
    if not model_paths:
        return

    for dotted in model_paths:
        model_class = apps.get_model(dotted)
        if model_class is None:
            continue
        if (
            model_class._meta.model_name == "auditlogentry"
            and model_class._meta.app_label == "security"
        ):
            continue

        post_save.connect(
            partial(_handle_save, backend), sender=model_class, weak=False
        )
        post_delete.connect(
            partial(_handle_delete, backend), sender=model_class, weak=False
        )
