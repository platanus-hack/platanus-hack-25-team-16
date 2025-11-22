"""
Collectors for extracting and sanitizing request/response data.
"""

import hashlib
import re
from typing import Dict, Any, Optional

from django.http import HttpRequest, HttpResponse

from ..registry import security_state


class RequestCollector:
    """
    Collects and sanitizes request data for audit logging.
    """

    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
        "x-csrf-token",
        "x-xsrf-token",
    }

    IMPORTANT_HEADERS = {
        "content-type",
        "accept",
        "referer",
        "origin",
        "x-requested-with",
        "user-agent",
        "accept-language",
        "accept-encoding",
    }

    def collect(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Extract relevant metadata from the request.

        Args:
            request: The Django HttpRequest object

        Returns:
            Dictionary containing sanitized request metadata
        """
        return {
            "endpoint": self._extract_endpoint(request.path),
            "content_type": request.META.get("CONTENT_TYPE", ""),
            "accept": request.META.get("HTTP_ACCEPT", ""),
            "referer": request.META.get("HTTP_REFERER", ""),
            "origin": request.META.get("HTTP_ORIGIN", ""),
            "body_hash": self._hash_body(request),
            "size": self._get_request_size(request),
            "query_params": self._sanitize_params(dict(request.GET)),
            "headers": self._collect_headers(request),
        }

    def _extract_endpoint(self, path: str) -> str:
        """
        Normalize the path to group similar endpoints.

        Examples:
            /api/v1/expenses/123/ -> /api/v1/expenses/{id}/
            /api/v1/users/abc-def-ghi/ -> /api/v1/users/{uuid}/
        """
        # Replace UUIDs with placeholder
        path = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "{uuid}",
            path,
            flags=re.IGNORECASE,
        )

        # Replace numeric IDs with placeholder
        path = re.sub(r"/\d+/", "/{id}/", path)
        path = re.sub(r"/\d+$", "/{id}", path)

        # Replace hex strings (potential tokens/hashes)
        path = re.sub(r"/[0-9a-f]{32,}/", "/{hash}/", path, flags=re.IGNORECASE)

        return path

    def _hash_body(self, request: HttpRequest) -> Optional[str]:
        """
        Calculate SHA256 hash of request body for integrity verification.
        """
        try:
            body = getattr(request, "_body", b"")
            if not body and hasattr(request, "body"):
                body = request.body

            if body:
                return hashlib.sha256(body).hexdigest()
        except Exception:
            # Body might not be available or readable
            pass
        return None

    def _get_request_size(self, request: HttpRequest) -> int:
        """
        Calculate the size of the request in bytes.
        """
        try:
            if hasattr(request, "_body"):
                return len(request._body)
            elif hasattr(request, "body"):
                return len(request.body)
        except Exception:
            pass

        # Fallback to Content-Length header
        content_length = request.META.get("CONTENT_LENGTH", "0")
        try:
            return int(content_length)
        except (ValueError, TypeError):
            return 0

    def _sanitize_params(self, params: Dict) -> Dict:
        """
        Sanitize query parameters, removing sensitive values.
        """
        try:
            from ..audit.sanitizer import sanitize_value

            policy = security_state.get_policy()
            return sanitize_value(params, policy)
        except Exception:
            # If policy not available, do basic sanitization
            return self._basic_sanitize(params)

    def _basic_sanitize(self, data: Dict) -> Dict:
        """
        Basic sanitization when policy is not available.
        """
        sensitive_keys = {"password", "token", "secret", "api_key", "auth"}
        sanitized = {}

        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized

    def _collect_headers(self, request: HttpRequest) -> Dict[str, str]:
        """
        Collect important headers, excluding sensitive ones.
        """
        headers = {}

        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].lower().replace("_", "-")

                # Skip sensitive headers
                if header_name in self.SENSITIVE_HEADERS:
                    continue

                # Include important headers or those starting with x-
                if header_name in self.IMPORTANT_HEADERS or header_name.startswith(
                    "x-"
                ):
                    # Limit header value length to prevent huge headers
                    headers[header_name] = value[:500] if len(value) > 500 else value

        return headers


class ResponseCollector:
    """
    Collects data from HTTP responses for audit logging.
    """

    def collect(self, response: HttpResponse, response_time_ms: int) -> Dict[str, Any]:
        """
        Extract metadata from the response.

        Args:
            response: The Django HttpResponse object
            response_time_ms: Response time in milliseconds

        Returns:
            Dictionary containing response metadata
        """
        return {
            "status": response.status_code,
            "response_time_ms": response_time_ms,
            "body_hash": self._hash_response_body(response),
            "size": self._calculate_size(response),
            "throttled": self._check_throttled(response),
            "rate_limit_remaining": self._get_rate_limit(response),
            "headers": self._collect_response_headers(response),
        }

    def _hash_response_body(self, response: HttpResponse) -> Optional[str]:
        """
        Calculate hash of response body (only for errors to aid debugging).
        """
        # Only hash error responses (4xx and 5xx)
        if response.status_code >= 400:
            try:
                content = response.content
                if content:
                    return hashlib.sha256(content).hexdigest()
            except Exception:
                # Content might not be accessible
                pass
        return None

    def _calculate_size(self, response: HttpResponse) -> int:
        """
        Calculate the size of the response in bytes.
        """
        try:
            return len(response.content)
        except Exception:
            # If content is not accessible, try Content-Length header
            content_length = response.get("Content-Length", "0")
            try:
                return int(content_length)
            except (ValueError, TypeError):
                return 0

    def _check_throttled(self, response: HttpResponse) -> bool:
        """
        Check if the request was rate limited.
        """
        # Standard rate limit status code
        if response.status_code == 429:
            return True

        # Check for rate limit headers
        if response.get("X-RateLimit-Remaining") == "0":
            return True

        return False

    def _get_rate_limit(self, response: HttpResponse) -> Optional[int]:
        """
        Extract rate limit information from response headers.
        """
        rate_limit = response.get("X-RateLimit-Remaining")
        if rate_limit:
            try:
                return int(rate_limit)
            except (ValueError, TypeError):
                pass
        return None

    def _collect_response_headers(self, response: HttpResponse) -> Dict[str, str]:
        """
        Collect important response headers for audit.
        """
        important_headers = [
            "content-type",
            "cache-control",
            "x-correlation-id",
            "x-request-id",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "etag",
            "last-modified",
            "location",  # For redirects
            "retry-after",  # For rate limiting
        ]

        headers = {}
        for header in important_headers:
            value = response.get(header)
            if value:
                headers[header] = str(value)[:500]  # Limit length

        return headers
