from __future__ import annotations

from django.utils.deprecation import MiddlewareMixin

from .context import update_context
from ..registry import security_state


class UserContextEnricher(MiddlewareMixin):
    """
    Actualiza el contexto con la identidad del usuario después de AuthenticationMiddleware.
    """

    def process_request(self, request):
        cfg = security_state.get_config()
        if not cfg.get("AUDIT_LOG", {}).get("ENABLED", True):
            return None

        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            update_context(actor=str(user.pk), actor_label=getattr(user, "get_username", lambda: "")())
        return None
