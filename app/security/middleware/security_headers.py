"""
Security Headers Middleware

Adds security headers to HTTP responses to protect against various attacks.
"""

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to responses.

    Configurable via DJANGO_SEC['CSP_POLICY'] and other settings.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

        # Get configuration
        self.config = getattr(settings, "DJANGO_SEC", {})
        self.enabled = self.config.get("ENABLE_SECURITY_HEADERS", True)

        # CSP configuration
        self.csp_policy = self.config.get("CSP_POLICY", "moderate")
        self.csp_report_only = self.config.get("CSP_REPORT_ONLY", False)
        self.csp_report_uri = self.config.get("CSP_REPORT_URI", None)

        # Build CSP based on policy
        self.csp_directives = self._build_csp_directives()

    def _build_csp_directives(self):
        """Build CSP directives based on policy setting."""
        if self.csp_policy == "strict":
            directives = {
                "default-src": "'self'",
                "script-src": "'self'",
                "style-src": "'self'",
                "img-src": "'self' data: https:",
                "font-src": "'self'",
                "connect-src": "'self'",
                "frame-ancestors": "'none'",
                "base-uri": "'self'",
                "form-action": "'self'",
                "upgrade-insecure-requests": "",
            }
        elif self.csp_policy == "moderate":
            directives = {
                "default-src": "'self'",
                "script-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
                "style-src": "'self' 'unsafe-inline' https://fonts.googleapis.com",
                "img-src": "'self' data: https:",
                "font-src": "'self' https://fonts.gstatic.com",
                "connect-src": "'self' https:",
                "frame-ancestors": "'self'",
                "base-uri": "'self'",
                "upgrade-insecure-requests": "",
            }
        elif self.csp_policy == "relaxed":
            directives = {
                "default-src": "'self' 'unsafe-inline' 'unsafe-eval' http: https: data:",
                "frame-ancestors": "'self'",
            }
        elif self.csp_policy == "custom":
            # Use custom directives from settings
            directives = self.config.get(
                "CSP_DIRECTIVES",
                {
                    "default-src": "'self'",
                },
            )
        else:
            # Default to moderate
            directives = {
                "default-src": "'self'",
                "script-src": "'self' 'unsafe-inline'",
                "style-src": "'self' 'unsafe-inline'",
            }

        # Add report-uri if configured
        if self.csp_report_uri:
            directives["report-uri"] = self.csp_report_uri

        return directives

    def _build_csp_header(self, directives=None):
        """Build the CSP header string from directives."""
        if directives is None:
            directives = self.csp_directives

        parts = []
        for directive, value in directives.items():
            if value:
                parts.append(f"{directive} {value}")
            else:
                parts.append(directive)

        return "; ".join(parts)

    def process_response(self, request, response):
        """Add security headers to response."""
        if not self.enabled:
            return response

        # Skip for admin and debug toolbar
        if request.path.startswith("/admin/") or request.path.startswith("/__debug__/"):
            return response

        # Content Security Policy
        if hasattr(request, "_csp_update"):
            # View has custom CSP updates
            custom_directives = self.csp_directives.copy()
            custom_directives.update(request._csp_update)
            csp_header = self._build_csp_header(custom_directives)
        elif hasattr(request, "_csp_exempt"):
            # View is exempt from CSP
            csp_header = None
        else:
            csp_header = self._build_csp_header()

        if csp_header:
            header_name = (
                "Content-Security-Policy-Report-Only"
                if self.csp_report_only
                else "Content-Security-Policy"
            )
            response[header_name] = csp_header

        # Referrer Policy
        if "Referrer-Policy" not in response:
            referrer_policy = self.config.get(
                "REFERRER_POLICY", "strict-origin-when-cross-origin"
            )
            response["Referrer-Policy"] = referrer_policy

        # Permissions Policy (formerly Feature Policy)
        if "Permissions-Policy" not in response:
            permissions = self.config.get(
                "PERMISSIONS_POLICY",
                {
                    "camera": "()",
                    "microphone": "()",
                    "geolocation": "()",
                    "payment": "()",
                    "usb": "()",
                    "magnetometer": "()",
                    "gyroscope": "()",
                    "accelerometer": "()",
                },
            )
            policy_parts = [
                f"{feature}={value}" for feature, value in permissions.items()
            ]
            response["Permissions-Policy"] = ", ".join(policy_parts)

        # X-Content-Type-Options
        if "X-Content-Type-Options" not in response:
            response["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options (if not using CSP frame-ancestors)
        if (
            "X-Frame-Options" not in response
            and "frame-ancestors" not in self.csp_directives
        ):
            x_frame = getattr(settings, "X_FRAME_OPTIONS", "DENY")
            response["X-Frame-Options"] = x_frame

        # Clear-Site-Data for logout responses
        if request.path == "/logout/" and response.status_code < 400:
            response["Clear-Site-Data"] = '"cache", "cookies", "storage"'

        # Additional security headers
        if not settings.DEBUG:
            # Strict-Transport-Security (handled by Django's SecurityMiddleware)
            pass

            # Cross-Origin headers
            if "Cross-Origin-Opener-Policy" not in response:
                response["Cross-Origin-Opener-Policy"] = "same-origin"

            if "Cross-Origin-Embedder-Policy" not in response:
                response["Cross-Origin-Embedder-Policy"] = "require-corp"

            if "Cross-Origin-Resource-Policy" not in response:
                response["Cross-Origin-Resource-Policy"] = "same-origin"

        return response


class CSPNonceMiddleware(MiddlewareMixin):
    """
    Middleware to add CSP nonces for inline scripts and styles.

    This is an optional enhancement for strict CSP policies.
    """

    def process_request(self, request):
        """Generate and store CSP nonce for this request."""
        import secrets

        request.csp_nonce = secrets.token_urlsafe(16)

    def process_response(self, request, response):
        """Add nonce to CSP header if present."""
        if hasattr(request, "csp_nonce") and "Content-Security-Policy" in response:
            csp = response["Content-Security-Policy"]
            nonce = f"'nonce-{request.csp_nonce}'"

            # Add nonce to script-src and style-src
            csp = csp.replace("script-src", f"script-src {nonce}")
            csp = csp.replace("style-src", f"style-src {nonce}")

            response["Content-Security-Policy"] = csp

        return response
