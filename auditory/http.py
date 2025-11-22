from __future__ import annotations

from typing import Any, Dict

from .registry import security_state


class HTTPProtectionMiddleware:
    """
    Middleware ligero que refuerza cabeceras HSTS/CSP/XFO sin romper SecurityMiddleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        cfg: Dict[str, Any] = security_state.get_config().get("HTTP_SECURITY", {})
        if not cfg.get("ENABLED", True):
            return response

        if cfg.get("HSTS_SECONDS"):
            value = f"max-age={int(cfg['HSTS_SECONDS'])}; includeSubDomains; preload"
            response.headers["Strict-Transport-Security"] = value

        if cfg.get("CSP_ENFORCE", True):
            response.headers.setdefault("Content-Security-Policy", "default-src 'self'")

        xfo = cfg.get("X_FRAME_OPTIONS")
        if xfo:
            response.headers["X-Frame-Options"] = xfo

        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response
