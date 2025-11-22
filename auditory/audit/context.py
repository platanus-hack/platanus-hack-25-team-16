import uuid
from contextvars import ContextVar
from typing import Any, Dict


audit_context: ContextVar[Dict[str, Any]] = ContextVar("audit_context", default={})


def reset_context() -> None:
    audit_context.set({})


def ensure_correlation_id() -> str:
    ctx = audit_context.get().copy()
    correlation_id = ctx.get("correlation_id") or str(uuid.uuid4())
    ctx["correlation_id"] = correlation_id
    audit_context.set(ctx)
    return correlation_id


def update_context(**kwargs: Any) -> Dict[str, Any]:
    ctx = audit_context.get().copy()
    ctx.update({k: v for k, v in kwargs.items() if v is not None})
    audit_context.set(ctx)
    return ctx
