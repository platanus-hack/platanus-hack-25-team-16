from __future__ import annotations

from io import BytesIO

from django.utils.deprecation import MiddlewareMixin

from .context import ensure_correlation_id, update_context
from .sanitizer import sanitize_body
from ..registry import security_state


def _get_client_ip(request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        parts = [ip.strip() for ip in xff.split(",") if ip.strip()]
        if parts:
            return parts[0]
    return request.META.get("REMOTE_ADDR")


class AuditContextMiddleware(MiddlewareMixin):
    """
    Captura contexto temprano (IP, UA, body, correlation-id) y lo deja en contextvars.
    """

    def process_request(self, request):
        cfg = security_state.get_config()
        audit_cfg = cfg.get("AUDIT_LOG", {})
        if not audit_cfg.get("ENABLED", True):
            return None

        correlation_id = ensure_correlation_id()
        ip = _get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "")
        max_body = audit_cfg.get("MAX_BODY_LENGTH")

        # Leer y reconstruir body para no romper el flujo posterior
        try:
            raw_body = request.body  # type: ignore[attr-defined]
        except Exception:
            raw_body = b""

        policy = security_state.get_policy()
        sanitized_body, parsed_body = sanitize_body(
            raw_body, policy, max_length=max_body
        )
        request._body = raw_body
        request._stream = BytesIO(raw_body)

        update_context(
            correlation_id=correlation_id,
            ip_address=ip,
            user_agent=ua,
            request_path=request.path,
            http_method=request.method,
            body=parsed_body,
        )

        request.correlation_id = correlation_id
        return None

    def process_response(self, request, response):
        correlation_id = getattr(request, "correlation_id", None)
        if correlation_id:
            response["X-Correlation-ID"] = correlation_id
        return response
