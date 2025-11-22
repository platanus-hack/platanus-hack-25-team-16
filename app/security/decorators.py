"""
Security Decorators

Provides decorators for view-level security controls.
"""

import functools
import hashlib
import time
from typing import Any, Callable, Dict, List, Optional, Union
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden, JsonResponse
from django.core.exceptions import ValidationError
from rest_framework.response import Response


def csp_update(**csp_directives) -> Callable:
    """
    Decorator to update CSP directives for a specific view.

    Args:
        **csp_directives: CSP directives to update

    Example:
        @csp_update(script_src="'self' https://cdn.example.com")
        def my_view(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Store CSP updates in request
            request._csp_update = csp_directives
            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def csp_exempt(view_func) -> Callable:
    """
    Decorator to exempt a view from CSP headers.

    Example:
        @csp_exempt
        def my_view(request):
            ...
    """

    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Mark request as CSP exempt
        request._csp_exempt = True
        return view_func(request, *args, **kwargs)

    return wrapped_view


def rate_limit(limit: str, key: str = "ip", block_duration: int = 60) -> Callable:
    """
    Decorator to apply rate limiting to a view.

    Args:
        limit: Rate limit string (e.g., '10/m', '100/h')
        key: Rate limit key ('ip', 'user', 'session')
        block_duration: Block duration in seconds after limit exceeded

    Example:
        @rate_limit('10/m', key='user')
        def api_view(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Parse limit
            if "/" in limit:
                count_str, period_str = limit.split("/")
                max_requests = int(count_str)

                # Parse period
                period_map = {"s": 1, "m": 60, "h": 3600, "d": 86400}
                period = period_map.get(period_str, 60)
            else:
                max_requests = int(limit)
                period = 3600

            # Generate rate limit key
            if key == "ip":
                x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
                if x_forwarded_for:
                    identifier = x_forwarded_for.split(",")[0].strip()
                else:
                    identifier = request.META.get("REMOTE_ADDR", "127.0.0.1")
            elif key == "user":
                if request.user and request.user.is_authenticated:
                    identifier = str(request.user.id)
                else:
                    return HttpResponseForbidden("Authentication required")
            elif key == "session":
                identifier = request.session.session_key
                if not identifier:
                    request.session.create()
                    identifier = request.session.session_key
            else:
                identifier = key

            # Create cache key
            view_name = f"{view_func.__module__}.{view_func.__name__}"
            cache_key = f"rate_limit:{view_name}:{identifier}"

            # Check rate limit
            current_time = time.time()
            requests = cache.get(cache_key, [])

            # Filter old requests
            cutoff_time = current_time - period
            requests = [req_time for req_time in requests if req_time > cutoff_time]

            # Check if limit exceeded
            if len(requests) >= max_requests:
                retry_after = int(period - (current_time - requests[0]))

                # Check if should block
                block_key = f"rate_limit_block:{view_name}:{identifier}"
                if cache.get(block_key):
                    return JsonResponse(
                        {
                            "error": "Rate limit exceeded",
                            "message": f"Too many requests. Blocked for {block_duration} seconds.",
                        },
                        status=429,
                    )

                # Set block if repeatedly hitting limit
                if len(requests) >= max_requests * 2:
                    cache.set(block_key, True, block_duration)

                response = JsonResponse(
                    {
                        "error": "Rate limit exceeded",
                        "message": f"Please try again in {retry_after} seconds",
                        "retry_after": retry_after,
                    },
                    status=429,
                )
                response["Retry-After"] = str(retry_after)
                return response

            # Add current request
            requests.append(current_time)
            cache.set(cache_key, requests, period)

            # Execute view
            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def validate_input(schema: Dict[str, Any]) -> Callable:
    """
    Decorator to validate request input.

    Args:
        schema: Validation schema

    Example:
        @validate_input({
            'email': 'email',
            'age': ('integer', {'min': 0, 'max': 120}),
        })
        def create_user(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            from app.security.validation import validate_input as validate_func

            # Get data based on request method
            if request.method in ["POST", "PUT", "PATCH"]:
                if hasattr(request, "data"):
                    # DRF request
                    data = request.data
                else:
                    # Django request
                    import json

                    try:
                        data = json.loads(request.body) if request.body else {}
                    except json.JSONDecodeError:
                        data = request.POST.dict()
            else:
                data = request.GET.dict()

            # Validate data
            try:
                validated_data = validate_func(data, schema)
                request.validated_data = validated_data
            except ValidationError as e:
                return JsonResponse(
                    {
                        "error": "Validation error",
                        "details": e.message_dict
                        if hasattr(e, "message_dict")
                        else str(e),
                    },
                    status=400,
                )
            except ValueError as e:
                return JsonResponse(
                    {
                        "error": "Validation error",
                        "message": str(e),
                    },
                    status=400,
                )

            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def secure_response(
    exclude_fields: Optional[List[str]] = None,
    sanitize_html_fields: Optional[List[str]] = None,
) -> Callable:
    """
    Decorator to sanitize response data.

    Args:
        exclude_fields: Fields to exclude from response
        sanitize_html_fields: Fields to sanitize HTML content

    Example:
        @secure_response(exclude_fields=['password', 'token'])
        def get_user(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            from app.security.validation import safe_json_response, sanitize_html

            response = view_func(request, *args, **kwargs)

            # Handle different response types
            if isinstance(response, JsonResponse):
                # Already a JsonResponse, modify its content
                import json

                data = json.loads(response.content.decode("utf-8"))
                sanitized_data = safe_json_response(data, exclude_fields)

                # Sanitize HTML fields if specified
                if sanitize_html_fields:
                    for field in sanitize_html_fields:
                        if field in sanitized_data and isinstance(
                            sanitized_data[field], str
                        ):
                            sanitized_data[field] = sanitize_html(sanitized_data[field])

                response.content = json.dumps(sanitized_data).encode("utf-8")

            elif isinstance(response, Response):
                # DRF Response
                sanitized_data = safe_json_response(response.data, exclude_fields)

                # Sanitize HTML fields if specified
                if sanitize_html_fields:
                    for field in sanitize_html_fields:
                        if field in sanitized_data and isinstance(
                            sanitized_data[field], str
                        ):
                            sanitized_data[field] = sanitize_html(sanitized_data[field])

                response.data = sanitized_data

            elif isinstance(response, dict):
                # Plain dictionary, convert to JsonResponse
                sanitized_data = safe_json_response(response, exclude_fields)

                # Sanitize HTML fields if specified
                if sanitize_html_fields:
                    for field in sanitize_html_fields:
                        if field in sanitized_data and isinstance(
                            sanitized_data[field], str
                        ):
                            sanitized_data[field] = sanitize_html(sanitized_data[field])

                response = JsonResponse(sanitized_data)

            return response

        return wrapped_view

    return decorator


def require_https(view_func) -> Callable:
    """
    Decorator to require HTTPS for a view.

    Example:
        @require_https
        def secure_view(request):
            ...
    """

    @functools.wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.is_secure() and not settings.DEBUG:
            return JsonResponse(
                {
                    "error": "HTTPS required",
                    "message": "This endpoint requires a secure connection",
                },
                status=403,
            )
        return view_func(request, *args, **kwargs)

    return wrapped_view


def cors_allow(
    origins: Union[str, List[str]] = "*",
    methods: Optional[List[str]] = None,
    headers: Optional[List[str]] = None,
) -> Callable:
    """
    Decorator to set CORS headers for a view.

    Args:
        origins: Allowed origins ('*' for all)
        methods: Allowed HTTP methods
        headers: Allowed headers

    Example:
        @cors_allow(origins='https://example.com', methods=['GET', 'POST'])
        def api_view(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)

            # Set CORS headers
            if origins == "*":
                response["Access-Control-Allow-Origin"] = "*"
            elif isinstance(origins, str):
                response["Access-Control-Allow-Origin"] = origins
            elif isinstance(origins, list):
                origin = request.META.get("HTTP_ORIGIN")
                if origin in origins:
                    response["Access-Control-Allow-Origin"] = origin

            if methods:
                response["Access-Control-Allow-Methods"] = ", ".join(methods)
            else:
                response["Access-Control-Allow-Methods"] = (
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
                )

            if headers:
                response["Access-Control-Allow-Headers"] = ", ".join(headers)
            else:
                response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

            response["Access-Control-Max-Age"] = "86400"  # 24 hours

            return response

        return wrapped_view

    return decorator


def audit_log(
    action: str, log_request: bool = True, log_response: bool = False
) -> Callable:
    """
    Decorator to add audit logging to a view.

    Args:
        action: Action name for logging
        log_request: Whether to log request data
        log_response: Whether to log response data

    Example:
        @audit_log('user_login', log_request=True)
        def login_view(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            import logging
            import json

            logger = logging.getLogger("security.audit")

            # Prepare audit log entry
            audit_entry = {
                "action": action,
                "timestamp": time.time(),
                "user": str(request.user.id)
                if request.user.is_authenticated
                else "anonymous",
                "ip": request.META.get("REMOTE_ADDR", "unknown"),
                "method": request.method,
                "path": request.path,
            }

            # Log request data if enabled
            if log_request:
                if request.method in ["POST", "PUT", "PATCH"]:
                    try:
                        if hasattr(request, "data"):
                            request_data = dict(request.data)
                        else:
                            request_data = (
                                json.loads(request.body) if request.body else {}
                            )

                        # Remove sensitive fields
                        for field in ["password", "token", "secret"]:
                            request_data.pop(field, None)

                        audit_entry["request_data"] = request_data
                    except Exception:
                        pass

            # Execute view
            try:
                response = view_func(request, *args, **kwargs)

                # Log response data if enabled
                if log_response and hasattr(response, "data"):
                    response_data = (
                        dict(response.data) if hasattr(response, "data") else {}
                    )
                    # Remove sensitive fields
                    for field in ["password", "token", "secret"]:
                        response_data.pop(field, None)
                    audit_entry["response_data"] = response_data

                audit_entry["status"] = "success"
                audit_entry["status_code"] = getattr(response, "status_code", 200)

            except Exception as e:
                audit_entry["status"] = "error"
                audit_entry["error"] = str(e)
                raise

            finally:
                # Log audit entry
                logger.info(json.dumps(audit_entry))

            return response

        return wrapped_view

    return decorator


def cache_response(
    timeout: int = 300, key_prefix: str = "", vary_on: Optional[List[str]] = None
) -> Callable:
    """
    Decorator to cache view responses.

    Args:
        timeout: Cache timeout in seconds
        key_prefix: Cache key prefix
        vary_on: List of request attributes to vary cache on

    Example:
        @cache_response(timeout=600, vary_on=['user'])
        def expensive_view(request):
            ...
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Build cache key
            key_parts = [key_prefix or view_func.__name__]

            if vary_on:
                for attr in vary_on:
                    if attr == "user" and request.user.is_authenticated:
                        key_parts.append(f"user:{request.user.id}")
                    elif attr == "GET":
                        key_parts.append(f"get:{request.GET.urlencode()}")
                    elif attr == "path":
                        key_parts.append(f"path:{request.path}")

            cache_key = ":".join(key_parts)
            cache_key = hashlib.md5(cache_key.encode()).hexdigest()

            # Check cache
            cached_response = cache.get(cache_key)
            if cached_response is not None:
                return cached_response

            # Execute view
            response = view_func(request, *args, **kwargs)

            # Cache response
            if response.status_code == 200:
                cache.set(cache_key, response, timeout)

            return response

        return wrapped_view

    return decorator
