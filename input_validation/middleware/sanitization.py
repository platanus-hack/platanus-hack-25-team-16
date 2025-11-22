"""
Request sanitization middleware.

Automatically sanitizes incoming request data to prevent:
- XSS attacks
- SQL injection
- HTML injection
- Other common attacks
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin

from ..sanitizers import DictSanitizer, InputSanitizer

logger = logging.getLogger(__name__)


class RequestSanitizationMiddleware(MiddlewareMixin):
    """
    Middleware that automatically sanitizes incoming request data.

    Configuration in settings.py:
        SANITIZATION_CONFIG = {
            'ENABLED': True,
            'SANITIZE_GET': True,
            'SANITIZE_POST': True,
            'SANITIZE_JSON': True,
            'HTML_FIELDS': ['description', 'content', 'bio'],
            'EMAIL_FIELDS': ['email', 'contact_email'],
            'URL_FIELDS': ['website', 'url', 'link'],
            'STRIP_TAGS': True,
            'EXCLUDE_PATHS': ['/admin/', '/static/'],
        }
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.config = getattr(settings, 'SANITIZATION_CONFIG', {})

        # Default configuration
        self.enabled = self.config.get('ENABLED', True)
        self.sanitize_get = self.config.get('SANITIZE_GET', True)
        self.sanitize_post = self.config.get('SANITIZE_POST', True)
        self.sanitize_json = self.config.get('SANITIZE_JSON', True)
        self.exclude_paths = self.config.get('EXCLUDE_PATHS', [])

        # Field-specific sanitization
        self.html_fields = self.config.get('HTML_FIELDS', [])
        self.email_fields = self.config.get('EMAIL_FIELDS', [])
        self.url_fields = self.config.get('URL_FIELDS', [])
        self.strip_tags = self.config.get('STRIP_TAGS', True)

        # Initialize sanitizers
        self.input_sanitizer = InputSanitizer()
        self.dict_sanitizer = DictSanitizer(
            html_fields=self.html_fields,
            email_fields=self.email_fields,
            url_fields=self.url_fields,
            strip_tags=self.strip_tags,
        )

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Sanitize incoming request data."""
        if not self.enabled:
            return None

        # Skip excluded paths
        if self._is_excluded_path(request.path):
            return None

        try:
            # Sanitize GET parameters
            if self.sanitize_get and request.GET:
                self._sanitize_query_dict(request.GET)

            # Sanitize POST parameters
            if self.sanitize_post and request.POST:
                self._sanitize_query_dict(request.POST)

            # Sanitize JSON body
            if self.sanitize_json and self._is_json_request(request):
                self._sanitize_json_body(request)

        except Exception as e:
            logger.error(f"Error sanitizing request: {str(e)}", exc_info=True)
            # Continue processing - sanitization errors shouldn't break the app

        return None

    def _is_excluded_path(self, path: str) -> bool:
        """Check if path should be excluded from sanitization."""
        for excluded_path in self.exclude_paths:
            if path.startswith(excluded_path):
                return True
        return False

    def _is_json_request(self, request: HttpRequest) -> bool:
        """Check if request contains JSON data."""
        content_type = request.content_type
        return content_type == 'application/json' or content_type.startswith('application/json')

    def _sanitize_query_dict(self, query_dict: Any) -> None:
        """
        Sanitize a QueryDict (GET or POST parameters).

        Note: QueryDict is mutable during request processing.
        """
        if not hasattr(query_dict, '_mutable'):
            return

        # Make mutable temporarily
        was_mutable = query_dict._mutable
        query_dict._mutable = True

        try:
            for key in list(query_dict.keys()):
                values = query_dict.getlist(key)
                sanitized_values = [
                    self._sanitize_value(key, value)
                    for value in values
                ]
                query_dict.setlist(key, sanitized_values)
        finally:
            # Restore original mutability
            query_dict._mutable = was_mutable

    def _sanitize_json_body(self, request: HttpRequest) -> None:
        """Sanitize JSON request body."""
        if not request.body:
            return

        try:
            # Parse JSON
            data = json.loads(request.body)

            # Sanitize
            if isinstance(data, dict):
                sanitized_data = self.dict_sanitizer.sanitize(data)
            elif isinstance(data, list):
                sanitized_data = [
                    self.dict_sanitizer.sanitize(item) if isinstance(item, dict) else item
                    for item in data
                ]
            else:
                sanitized_data = data

            # Store sanitized data for access in views
            request._sanitized_data = sanitized_data

        except json.JSONDecodeError:
            # Not valid JSON, skip sanitization
            pass
        except Exception as e:
            logger.error(f"Error sanitizing JSON body: {str(e)}", exc_info=True)

    def _sanitize_value(self, key: str, value: Any) -> Any:
        """Sanitize a single value based on its key."""
        if not isinstance(value, str):
            return value

        # Apply field-specific sanitization
        if key in self.email_fields:
            return self.input_sanitizer.sanitize_email(value)

        elif key in self.url_fields:
            return self.input_sanitizer.sanitize_url(value)

        elif key in self.html_fields:
            return self.input_sanitizer.sanitize_html(value, strip_tags=self.strip_tags)

        # Default: basic sanitization
        return self.input_sanitizer.sanitize_html(value, strip_tags=True)


class ContentSecurityPolicyMiddleware(MiddlewareMixin):
    """
    Middleware that adds Content Security Policy headers to responses.

    This helps prevent XSS attacks by controlling which resources can be loaded.

    Configuration in settings.py:
        CSP_CONFIG = {
            'ENABLED': True,
            'REPORT_ONLY': False,  # Set to True to only report violations
            'DIRECTIVES': {
                'default-src': ["'self'"],
                'script-src': ["'self'", "'unsafe-inline'"],
                'style-src': ["'self'", "'unsafe-inline'"],
                'img-src': ["'self'", 'data:', 'https:'],
                'font-src': ["'self'"],
                'connect-src': ["'self'"],
                'frame-ancestors': ["'none'"],
                'base-uri': ["'self'"],
                'form-action': ["'self'"],
            }
        }
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.config = getattr(settings, 'CSP_CONFIG', {})

        self.enabled = self.config.get('ENABLED', True)
        self.report_only = self.config.get('REPORT_ONLY', False)
        self.directives = self.config.get('DIRECTIVES', {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'"],
            'img-src': ["'self'", 'data:', 'https:'],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'frame-ancestors': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
        })

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Add CSP header to response."""
        if not self.enabled:
            return response

        # Build CSP header value
        csp_parts = []
        for directive, values in self.directives.items():
            if values:
                values_str = ' '.join(values)
                csp_parts.append(f"{directive} {values_str}")

        csp_value = '; '.join(csp_parts)

        # Add header
        header_name = 'Content-Security-Policy-Report-Only' if self.report_only else 'Content-Security-Policy'
        response[header_name] = csp_value

        return response


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware that adds various security headers to responses.

    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: various
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.config = getattr(settings, 'SECURITY_HEADERS_CONFIG', {})

        self.enabled = self.config.get('ENABLED', True)

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Add security headers to response."""
        if not self.enabled:
            return response

        # Prevent MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        if 'X-Frame-Options' not in response:
            response['X-Frame-Options'] = 'DENY'

        # XSS protection (legacy but still useful)
        response['X-XSS-Protection'] = '1; mode=block'

        # Referrer policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions policy (formerly Feature-Policy)
        permissions = [
            'camera=()',
            'microphone=()',
            'geolocation=()',
            'payment=()',
            'usb=()',
        ]
        response['Permissions-Policy'] = ', '.join(permissions)

        return response


class RequestSizeLimitMiddleware(MiddlewareMixin):
    """
    Middleware that enforces maximum request size limits to prevent DoS attacks.

    Configuration in settings.py:
        REQUEST_SIZE_LIMITS = {
            'ENABLED': True,
            'MAX_BODY_SIZE': 10 * 1024 * 1024,  # 10 MB
            'MAX_JSON_SIZE': 1 * 1024 * 1024,   # 1 MB
        }
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.config = getattr(settings, 'REQUEST_SIZE_LIMITS', {})

        self.enabled = self.config.get('ENABLED', True)
        self.max_body_size = self.config.get('MAX_BODY_SIZE', 10 * 1024 * 1024)  # 10 MB
        self.max_json_size = self.config.get('MAX_JSON_SIZE', 1 * 1024 * 1024)   # 1 MB

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Check request size limits."""
        if not self.enabled:
            return None

        # Get content length
        content_length = request.META.get('CONTENT_LENGTH')
        if not content_length:
            return None

        try:
            content_length = int(content_length)
        except (ValueError, TypeError):
            return JsonResponse(
                {'error': 'Invalid Content-Length header'},
                status=400
            )

        # Check against max body size
        if content_length > self.max_body_size:
            return JsonResponse(
                {'error': f'Request body too large. Maximum size is {self.max_body_size} bytes.'},
                status=413
            )

        # Check against max JSON size for JSON requests
        if self._is_json_request(request) and content_length > self.max_json_size:
            return JsonResponse(
                {'error': f'JSON payload too large. Maximum size is {self.max_json_size} bytes.'},
                status=413
            )

        return None

    def _is_json_request(self, request: HttpRequest) -> bool:
        """Check if request contains JSON data."""
        content_type = request.META.get('CONTENT_TYPE', '')
        return content_type.startswith('application/json')
