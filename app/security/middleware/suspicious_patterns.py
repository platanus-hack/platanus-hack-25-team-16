"""
Suspicious Patterns Middleware

Detects and blocks suspicious request patterns that may indicate attacks.
"""

import re
import json
from collections import defaultdict
from datetime import datetime, timedelta
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse, HttpResponseForbidden
from django.core.cache import cache


class SuspiciousPatternsMiddleware(MiddlewareMixin):
    """
    Middleware to detect and block suspicious request patterns.

    Detects:
    - Common exploit paths (/wp-admin, /.env, etc.)
    - SQL injection attempts
    - XSS attempts
    - Path traversal
    - Known scanner User-Agents
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

        # Get configuration
        self.config = getattr(settings, "DJANGO_SEC", {})
        self.enabled = self.config.get("ENABLE_SUSPICIOUS_PATTERNS", True)

        # Action configuration
        self.action = self.config.get(
            "SUSPICIOUS_ACTION", "block"
        )  # log, block, degrade
        self.threshold = self.config.get(
            "SUSPICIOUS_THRESHOLD", 5
        )  # Auto-block after N violations
        self.block_duration = self.config.get("BLOCK_DURATION", 3600)  # 1 hour

        # Debug: print configuration on startup
        if settings.DEBUG:
            print(
                f"[SuspiciousPatternsMiddleware] Initialized with: enabled={self.enabled}, action={self.action}"
            )

        # Initialize patterns
        self._init_patterns()

        # Track violations
        self.violations = defaultdict(list)

    def _init_patterns(self):
        """Initialize suspicious patterns to detect."""
        # Suspicious paths
        self.suspicious_paths = [
            r"/\.env",
            r"/\.git",
            r"/\.aws",
            r"/\.ssh",
            r"/wp-admin",
            r"/wp-login",
            r"/phpmyadmin",
            r"/phpMyAdmin",
            r"/admin\.php",
            r"/config\.php",
            r"/install\.php",
            r"/setup\.php",
            r"/backup\.",
            r"/database\.",
            r"/db\.",
            r"/sql\.",
            r"/dump\.",
            r"/\.htaccess",
            r"/web\.config",
            r"/composer\.json",
            r"/package\.json",
            r"/node_modules",
            r"/vendor/",
            r"/\.DS_Store",
            r"/Thumbs\.db",
            r"/\.svn",
            r"/\.hg",
            r"/\.bzr",
            r"/.well-known/security.txt",
        ]

        # SQL injection patterns
        self.sql_injection_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
            r"(\binsert\b.*\binto\b.*\bvalues\b)",
            r"(\bdelete\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"(\bupdate\b.*\bset\b)",
            r"(\bexec\b|\bexecute\b)",
            r"(\bscript\b.*\bsrc\b)",
            r"(1\s*=\s*1)",
            r"(\bor\b\s+1\s*=\s*1)",
            r"(\band\b\s+1\s*=\s*1)",
            r"(;\s*--)",
            r"('\s*or\s*')",
            r"(\bwaitfor\b.*\bdelay\b)",
            r"(\bbenchmark\b.*\bmd5\b)",
            r"(\bsleep\b\s*\()",
        ]

        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",  # onclick=, onload=, etc.
            r"<iframe[^>]*>",
            r"<embed[^>]*>",
            r"<object[^>]*>",
            r"<img[^>]*on\w+",
            r"<svg[^>]*on\w+",
            r"<body[^>]*on\w+",
            r"document\.(cookie|write|location)",
            r"window\.(location|open)",
            r"eval\s*\(",
            r"expression\s*\(",
            r"<marquee[^>]*>",
            r"<blink[^>]*>",
            r"style\s*=.*expression",
            r"style\s*=.*javascript",
        ]

        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./\.\.",
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"\.\.%2f",
            r"%2e%2e%5c",
            r"\.\.%5c",
            r"\.\.%c0%af",
            r"\.\.%c1%9c",
        ]

        # Suspicious User-Agents
        self.suspicious_user_agents = [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"metasploit",
            r"burp",
            r"havij",
            r"acunetix",
            r"nessus",
            r"openvas",
            r"w3af",
            r"webscarab",
            r"paros",
            r"dirbuster",
            r"wfuzz",
            r"hydra",
            r"medusa",
            r"brutus",
            r"john",
            r"aircrack",
            r"hashcat",
            r"zgrab",
            r"masscan",
            r"nuclei",
        ]

        # Compile patterns for efficiency
        self.compiled_patterns = {
            "paths": [re.compile(p, re.IGNORECASE) for p in self.suspicious_paths],
            "sql": [re.compile(p, re.IGNORECASE) for p in self.sql_injection_patterns],
            "xss": [re.compile(p, re.IGNORECASE) for p in self.xss_patterns],
            "traversal": [
                re.compile(p, re.IGNORECASE) for p in self.path_traversal_patterns
            ],
            "user_agents": [
                re.compile(p, re.IGNORECASE) for p in self.suspicious_user_agents
            ],
        }

    def _get_client_ip(self, request):
        """Get the client IP address from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "127.0.0.1")
        return ip

    def _check_blocked(self, ip):
        """Check if IP is blocked."""
        cache_key = f"blocked_ip:{ip}"
        return cache.get(cache_key, False)

    def _block_ip(self, ip, reason):
        """Block an IP address."""
        cache_key = f"blocked_ip:{ip}"
        cache.set(
            cache_key,
            {
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
            },
            self.block_duration,
        )

    def _check_patterns(self, text, pattern_list):
        """Check text against a list of compiled patterns."""
        for pattern in pattern_list:
            if pattern.search(text):
                return True
        return False

    def _detect_suspicious_patterns(self, request):
        """Detect suspicious patterns in request."""
        detections = []

        # Check path
        path = request.path
        if self._check_patterns(path, self.compiled_patterns["paths"]):
            detections.append(("suspicious_path", path))

        # Check query string
        query_string = request.META.get("QUERY_STRING", "")
        if query_string:
            # Decode URL-encoded query string for pattern matching
            from urllib.parse import unquote_plus

            decoded_query = unquote_plus(query_string)

            if settings.DEBUG:
                print(
                    f"[SuspiciousPatternsMiddleware] Query string (raw): {query_string}"
                )
                print(
                    f"[SuspiciousPatternsMiddleware] Query string (decoded): {decoded_query}"
                )

            # Check for SQL injection in both encoded and decoded versions
            if self._check_patterns(
                query_string, self.compiled_patterns["sql"]
            ) or self._check_patterns(decoded_query, self.compiled_patterns["sql"]):
                detections.append(("sql_injection", query_string))

            # Check for XSS in both encoded and decoded versions
            if self._check_patterns(
                query_string, self.compiled_patterns["xss"]
            ) or self._check_patterns(decoded_query, self.compiled_patterns["xss"]):
                detections.append(("xss_attempt", query_string))

            # Check for path traversal in both encoded and decoded versions
            if self._check_patterns(
                query_string, self.compiled_patterns["traversal"]
            ) or self._check_patterns(
                decoded_query, self.compiled_patterns["traversal"]
            ):
                detections.append(("path_traversal", query_string))

        # Check User-Agent
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        if self._check_patterns(user_agent, self.compiled_patterns["user_agents"]):
            detections.append(("suspicious_user_agent", user_agent))

        # Check request body for POST requests
        if request.method == "POST":
            try:
                if hasattr(request, "body"):
                    body = request.body.decode("utf-8", errors="ignore")[
                        :1000
                    ]  # Limit check to first 1000 chars

                    if self._check_patterns(body, self.compiled_patterns["sql"]):
                        detections.append(("sql_injection_body", "POST body"))

                    if self._check_patterns(body, self.compiled_patterns["xss"]):
                        detections.append(("xss_attempt_body", "POST body"))
            except Exception:
                pass

        # Check headers
        suspicious_headers = [
            "HTTP_X_FORWARDED_HOST",
            "HTTP_X_ORIGINAL_URL",
            "HTTP_X_REWRITE_URL",
        ]

        for header in suspicious_headers:
            header_value = request.META.get(header, "")
            if header_value:
                if self._check_patterns(
                    header_value, self.compiled_patterns["traversal"]
                ):
                    detections.append(
                        ("suspicious_header", f"{header}: {header_value}")
                    )

        return detections

    def _log_violation(self, ip, detections):
        """Log security violation."""
        if settings.DEBUG:
            print(f"Security violation from {ip}:")
            for detection_type, detection_value in detections:
                print(f"  - {detection_type}: {detection_value[:100]}")

        # Track violations for auto-blocking
        self.violations[ip].append(
            {
                "timestamp": datetime.now(),
                "detections": detections,
            }
        )

        # Clean old violations
        cutoff = datetime.now() - timedelta(seconds=3600)
        self.violations[ip] = [
            v for v in self.violations[ip] if v["timestamp"] > cutoff
        ]

        # Auto-block if threshold exceeded
        if len(self.violations[ip]) >= self.threshold:
            self._block_ip(
                ip,
                f"Exceeded violation threshold: {len(self.violations[ip])} violations",
            )
            return True

        return False

    def process_request(self, request):
        """Check request for suspicious patterns."""
        if not self.enabled:
            if settings.DEBUG:
                print("[SuspiciousPatternsMiddleware] Disabled - skipping check")
            return None

        # Get client IP
        ip = self._get_client_ip(request)

        # Check if IP is blocked
        if self._check_blocked(ip):
            return HttpResponseForbidden(
                json.dumps(
                    {
                        "error": "Forbidden",
                        "message": "Your IP has been temporarily blocked due to suspicious activity.",
                    }
                ),
                content_type="application/json",
            )

        # Detect suspicious patterns
        detections = self._detect_suspicious_patterns(request)

        if settings.DEBUG and request.path.startswith("/api/"):
            print(
                f"[SuspiciousPatternsMiddleware] Path: {request.path}, Detections: {len(detections)}, Action: {self.action}"
            )

        if detections:
            # Log violation
            auto_blocked = self._log_violation(ip, detections)

            if settings.DEBUG:
                print(f"[SuspiciousPatternsMiddleware] DETECTIONS FOUND: {detections}")
                print(
                    f"[SuspiciousPatternsMiddleware] Action={self.action}, AutoBlocked={auto_blocked}"
                )
                print(
                    f"[SuspiciousPatternsMiddleware] Will block: {self.action == 'block' or auto_blocked}"
                )

            # Take action based on configuration
            if self.action == "block" or auto_blocked:
                if settings.DEBUG:
                    print("[SuspiciousPatternsMiddleware] BLOCKING REQUEST!")
                return HttpResponseForbidden(
                    json.dumps(
                        {
                            "error": "Forbidden",
                            "message": "Suspicious request pattern detected.",
                        }
                    ),
                    content_type="application/json",
                )
            elif self.action == "degrade":
                # Mark request for degraded service
                request._degraded_service = True
                request._security_detections = detections
            # If action is 'log', just continue

        return None


class HoneypotMiddleware(MiddlewareMixin):
    """
    Middleware to implement honeypot traps.

    Detects bots by including hidden form fields that humans won't fill.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

        self.config = getattr(settings, "DJANGO_SEC", {})
        self.enabled = self.config.get("ENABLE_HONEYPOT", False)
        self.honeypot_field = self.config.get("HONEYPOT_FIELD", "website")

    def process_request(self, request):
        """Check for honeypot field in form submissions."""
        if not self.enabled:
            return None

        if request.method == "POST":
            # Check for honeypot field
            if self.honeypot_field in request.POST:
                honeypot_value = request.POST.get(self.honeypot_field)

                # If honeypot field is filled, it's likely a bot
                if honeypot_value:
                    ip = self._get_client_ip(request)

                    if settings.DEBUG:
                        print(f"Honeypot triggered by {ip}: {honeypot_value}")

                    return JsonResponse(
                        {
                            "error": "Invalid request",
                            "message": "Your request has been rejected.",
                        },
                        status=400,
                    )

        return None

    def _get_client_ip(self, request):
        """Get the client IP address from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "127.0.0.1")
        return ip
