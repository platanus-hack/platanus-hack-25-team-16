"""
Middleware for comprehensive API request logging.
"""

import time
import logging
import traceback
import hashlib
import json
from typing import Dict, Any, Optional

from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin

from .models import APIRequestLog
from .collectors import RequestCollector, ResponseCollector
from ..audit.context import audit_context
from ..registry import security_state


logger = logging.getLogger(__name__)


class APIRequestLoggingMiddleware(MiddlewareMixin):
    """
    Capture comprehensive request/response metadata for ISO27001 compliance.
    Should be placed AFTER UserContextEnricher in the middleware stack.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.request_collector = RequestCollector()
        self.response_collector = ResponseCollector()
        super().__init__(get_response)

    def process_request(self, request: HttpRequest) -> None:
        """
        Mark request start time and collect request data.
        """
        # Store start time for latency calculation
        request._api_start_time = time.time()

        # Collect request data early
        try:
            request._api_request_data = self.request_collector.collect(request)
        except Exception as e:
            logger.warning(f"Failed to collect request data: {e}")
            request._api_request_data = {}

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """
        Capture response data and log the complete request/response cycle.
        """
        try:
            # Check if logging is enabled
            cfg = security_state.get_config()
            api_cfg = cfg.get("API_REQUEST_LOG", {})

            if not api_cfg.get("ENABLED", True):
                return response

            # Check if path should be excluded
            if self._should_exclude_path(request.path, api_cfg):
                return response

            # Check sampling rate
            if not self._should_sample(api_cfg):
                return response

            # Calculate response time
            start_time = getattr(request, "_api_start_time", time.time())
            response_time_ms = int((time.time() - start_time) * 1000)

            # Get audit context (from AuditContextMiddleware)
            ctx = audit_context.get()

            # Get request data collected earlier
            request_data = getattr(request, "_api_request_data", {})

            # Collect response data
            response_data = self.response_collector.collect(response, response_time_ms)

            # Build complete log entry
            log_entry = self._build_log_entry(request, request_data, response_data, ctx)

            # Save log entry asynchronously to avoid blocking
            self._save_log_entry(log_entry, api_cfg)

        except Exception as e:
            logger.error(f"Failed to log API request: {e}", exc_info=True)

        return response

    def process_exception(
        self, request: HttpRequest, exception: Exception
    ) -> Optional[HttpResponse]:
        """
        Log unhandled exceptions with full context.
        """
        try:
            # Check if logging is enabled
            cfg = security_state.get_config()
            api_cfg = cfg.get("API_REQUEST_LOG", {})

            if not api_cfg.get("ENABLED", True):
                return None

            # Calculate response time
            start_time = getattr(request, "_api_start_time", time.time())
            response_time_ms = int((time.time() - start_time) * 1000)

            # Get context
            ctx = audit_context.get()
            request_data = getattr(request, "_api_request_data", {})

            # Build exception log entry
            log_entry = self._build_exception_log_entry(
                request, request_data, exception, response_time_ms, ctx
            )

            # Save log entry
            self._save_log_entry(log_entry, api_cfg)

        except Exception as e:
            logger.error(f"Failed to log exception: {e}", exc_info=True)

        return None

    def _should_exclude_path(self, path: str, config: Dict[str, Any]) -> bool:
        """
        Check if the path should be excluded from logging.
        """
        exclude_paths = config.get("EXCLUDE_PATHS", [])
        for pattern in exclude_paths:
            if path.startswith(pattern):
                return True
        return False

    def _should_sample(self, config: Dict[str, Any]) -> bool:
        """
        Determine if this request should be logged based on sampling rate.
        """
        import random

        sampling_rate = config.get("SAMPLING_RATE", 1.0)
        return random.random() < sampling_rate

    def _build_log_entry(
        self,
        request: HttpRequest,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build the complete log entry dictionary.
        """
        # Extract user information
        user = getattr(request, "user", None)
        user_id = None
        username = None

        if user and hasattr(user, "is_authenticated") and user.is_authenticated:
            user_id = getattr(user, "id", None)
            username = getattr(user, "username", None) or str(user) if user else None

        # Determine authentication method
        auth_method = self._get_auth_method(request)

        # Extract API metadata
        api_version = self._extract_api_version(request.path)
        resource_type, resource_id = self._extract_resource_info(request.path)

        # Get IP address - try context first, then request directly
        ip_address = context.get("ip_address")
        if not ip_address:
            # Fallback: try to get IP from request directly
            xff = request.META.get("HTTP_X_FORWARDED_FOR")
            if xff:
                parts = [ip.strip() for ip in xff.split(",") if ip.strip()]
                if parts:
                    ip_address = parts[0]
            if not ip_address:
                ip_address = request.META.get("REMOTE_ADDR")

        return {
            # Context from AuditContextMiddleware
            "correlation_id": context.get("correlation_id", ""),
            "ip_address": ip_address,
            "user_agent": context.get("user_agent", ""),
            # User information
            "user_id": user_id or context.get("actor"),
            "username": username or context.get("actor_label"),
            "session_id": self._get_session_id(request),
            # Request details
            "endpoint": request_data.get("endpoint", ""),
            "http_method": request.method,
            "request_path": request.get_full_path(),
            "content_type": request_data.get("content_type", ""),
            "accept": request_data.get("accept", ""),
            "referer": request_data.get("referer", ""),
            "origin": request_data.get("origin", ""),
            "request_body_hash": request_data.get("body_hash"),
            "request_size": request_data.get("size", 0),
            "query_params": request_data.get("query_params", {}),
            # Response details
            "response_status": response_data.get("status", 0),
            "response_time_ms": response_data.get("response_time_ms", 0),
            "response_body_hash": response_data.get("body_hash"),
            "response_size": response_data.get("size", 0),
            "response_headers": response_data.get("headers", {}),
            # Security metrics
            "auth_method": auth_method,
            "auth_success": response_data.get("status") != 401,
            "throttled": response_data.get("throttled", False),
            "rate_limit_remaining": response_data.get("rate_limit_remaining"),
            # API metadata
            "api_version": api_version,
            "api_type": "rest",  # Can be extended for GraphQL, WebSocket, etc.
            "resource_type": resource_type,
            "resource_id": resource_id,
        }

    def _build_exception_log_entry(
        self,
        request: HttpRequest,
        request_data: Dict[str, Any],
        exception: Exception,
        response_time_ms: int,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build log entry for unhandled exceptions.
        """
        # Get base log entry
        log_entry = self._build_log_entry(
            request,
            request_data,
            {"status": 500, "response_time_ms": response_time_ms},
            context,
        )

        # Add exception details
        tb_str = traceback.format_exc()
        log_entry.update(
            {
                "response_status": 500,
                "error_message": str(exception),
                "traceback_hash": hashlib.sha256(tb_str.encode()).hexdigest(),
                "auth_success": False,  # Assume failure for exceptions
            }
        )

        return log_entry

    def _get_auth_method(self, request: HttpRequest) -> Optional[str]:
        """
        Determine the authentication method used.
        """
        # Check Authorization header
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        if auth_header.startswith("Bearer"):
            return "jwt"
        elif auth_header.startswith("Token"):
            return "apikey"
        elif auth_header.startswith("Basic"):
            return "basic"

        # Check for session authentication
        if hasattr(request, "user") and request.user.is_authenticated:
            if hasattr(request, "session") and request.session.session_key:
                return "session"

        # Check for API key in headers or query params
        if request.META.get("HTTP_X_API_KEY"):
            return "apikey"

        return None

    def _get_session_id(self, request: HttpRequest) -> Optional[str]:
        """
        Extract session ID if available.
        """
        if hasattr(request, "session"):
            return request.session.session_key
        return None

    def _extract_api_version(self, path: str) -> Optional[str]:
        """
        Extract API version from path (e.g., /api/v1/... -> v1).
        """
        import re

        match = re.search(r"/api/(v\d+)/", path)
        if match:
            return match.group(1)
        return None

    def _extract_resource_info(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extract resource type and ID from path.

        Examples:
            /api/v1/expenses/123/ -> ('expenses', '123')
            /api/v1/users/ -> ('users', None)
            /admin/auth/user/5/change/ -> ('user', '5')
        """
        import re

        # Handle Django admin paths
        if path.startswith("/admin/"):
            # Pattern: /admin/{app_label}/{model_name}/{id?}/...
            admin_match = re.search(r"/admin/([^/]+)/([^/]+)(?:/(\d+))?/", path)
            if admin_match:
                app_label = admin_match.group(1)
                model_name = admin_match.group(2)
                resource_id = admin_match.group(3)

                # Combine app_label and model for better context
                resource_type = f"{app_label}.{model_name}"
                return resource_type, resource_id

            return None, None

        # Remove API version prefix
        path = re.sub(r"^/api/v\d+/", "", path)

        # Split path segments
        segments = [s for s in path.strip("/").split("/") if s]

        if not segments:
            return None, None

        resource_type = segments[0]
        resource_id = (
            segments[1] if len(segments) > 1 and segments[1].isdigit() else None
        )

        return resource_type, resource_id

    def _save_log_entry(self, log_data: Dict[str, Any], config: Dict[str, Any]) -> None:
        """
        Save the log entry with cryptographic integrity.
        """
        try:
            # Get the backend and save
            backend = security_state.get_backend()

            # Check if backend supports API logging
            if hasattr(backend, "append_api_log"):
                backend.append_api_log(log_data)
            else:
                # Fallback to direct database save (without hash chain)
                self._direct_save(log_data)

        except Exception as e:
            logger.error(f"Failed to save API log entry: {e}", exc_info=True)

    def _direct_save(self, log_data: Dict[str, Any]) -> None:
        """
        Direct database save without hash chain (fallback).
        """
        # Remove None values
        log_data = {k: v for k, v in log_data.items() if v is not None}

        # Set default hashes if not using hash chain
        if "hash_prev" not in log_data:
            log_data["hash_prev"] = "0" * 64
        if "hash_current" not in log_data:
            log_data["hash_current"] = hashlib.sha256(
                json.dumps(log_data, sort_keys=True).encode()
            ).hexdigest()

        # Create the log entry
        APIRequestLog.objects.create(**log_data)
