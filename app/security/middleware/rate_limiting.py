"""
Rate Limiting Middleware

Implements rate limiting to prevent abuse and DoS attacks.
"""

import time
import hashlib
from collections import defaultdict
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.core.cache import cache


class RateLimitingMiddleware(MiddlewareMixin):
    """
    Middleware to implement rate limiting.

    Supports multiple strategies:
    - Fixed Window
    - Sliding Window
    - Token Bucket

    Configurable via DJANGO_SEC['RATE_LIMITING'] settings.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

        # Get configuration
        self.config = getattr(settings, "DJANGO_SEC", {})
        self.rate_config = self.config.get("RATE_LIMITING", {})
        self.enabled = self.config.get("ENABLE_RATE_LIMITING", True)

        # Backend configuration
        self.backend = self.rate_config.get("BACKEND", "cache")
        self.strategy = self.rate_config.get("STRATEGY", "sliding_window")

        # Default limits
        default_limits = self.rate_config.get(
            "DEFAULT_LIMITS",
            {
                "anonymous": "100/h",
                "authenticated": "1000/h",
            },
        )
        self.default_limits = self._parse_limits(default_limits)

        # Endpoint-specific limits
        endpoint_limits = self.rate_config.get(
            "ENDPOINT_LIMITS",
            {
                "/api/login/": "5/m",
                "/api/register/": "10/h",
                "/api/password-reset/": "3/h",
            },
        )
        self.endpoint_limits = self._parse_limits(endpoint_limits)

        # In-memory storage for development (not recommended for production)
        self.memory_storage = defaultdict(list)

    def _parse_limits(self, limits):
        """Parse rate limit strings into tuples of (count, period_seconds)."""
        parsed = {}
        for key, limit_str in limits.items():
            if "/" in limit_str:
                count, period = limit_str.split("/")
                count = int(count)

                # Parse period
                period_map = {
                    "s": 1,
                    "m": 60,
                    "h": 3600,
                    "d": 86400,
                }
                period_seconds = period_map.get(period, 3600)
                parsed[key] = (count, period_seconds)
            else:
                # Default to per hour if no period specified
                parsed[key] = (int(limit_str), 3600)

        return parsed

    def _get_client_ip(self, request):
        """Get the client IP address from request."""
        # Check for proxy headers
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "127.0.0.1")

        return ip

    def _get_rate_limit_key(self, request):
        """Generate a unique key for rate limiting."""
        # Get identifier (IP for anonymous, user ID for authenticated)
        # Use hasattr to safely check if user attribute exists (may not be available yet if
        # this middleware runs before AuthenticationMiddleware)
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            identifier = f"user:{request.user.id}"
            limit_type = "authenticated"
        else:
            identifier = f"ip:{self._get_client_ip(request)}"
            limit_type = "anonymous"

        # Include path for endpoint-specific limits
        path = request.path
        key_parts = [identifier, path, request.method]
        key = hashlib.md5(":".join(key_parts).encode()).hexdigest()

        return key, limit_type

    def _get_limit_for_request(self, request, limit_type):
        """Get the rate limit for a specific request."""
        # Check endpoint-specific limits first
        path = request.path
        for endpoint_pattern, limit in self.endpoint_limits.items():
            if path.startswith(endpoint_pattern):
                return limit

        # Fall back to default limits
        return self.default_limits.get(limit_type, (100, 3600))

    def _check_rate_limit_sliding_window(self, key, limit, period):
        """Check rate limit using sliding window strategy."""
        current_time = time.time()
        window_start = current_time - period

        if self.backend == "redis":
            # Redis implementation
            try:
                import redis

                r = redis.from_url(settings.REDIS_URL, decode_responses=True)

                # Remove old entries
                r.zremrangebyscore(key, 0, window_start)

                # Count requests in window
                count = r.zcard(key)

                if count >= limit:
                    return False

                # Add current request
                r.zadd(key, {str(current_time): current_time})
                r.expire(key, period)
                return True
            except Exception:
                # Fall back to cache backend
                pass

        if self.backend == "cache":
            # Django cache implementation
            cache_key = f"rate_limit:{key}"
            requests = cache.get(cache_key, [])

            # Filter old requests
            requests = [req_time for req_time in requests if req_time > window_start]

            if len(requests) >= limit:
                return False

            # Add current request
            requests.append(current_time)
            cache.set(cache_key, requests, period)
            return True

        # Memory backend (development only)
        requests = self.memory_storage[key]
        requests = [req_time for req_time in requests if req_time > window_start]
        self.memory_storage[key] = requests

        if len(requests) >= limit:
            return False

        self.memory_storage[key].append(current_time)
        return True

    def _check_rate_limit_fixed_window(self, key, limit, period):
        """Check rate limit using fixed window strategy."""
        if self.backend in ("redis", "cache"):
            cache_key = f"rate_limit_fixed:{key}"
            window_key = f"{cache_key}:{int(time.time() // period)}"

            if self.backend == "cache":
                count = cache.get(window_key, 0)
                if count >= limit:
                    return False
                cache.set(window_key, count + 1, period)
                return True

        # Memory backend
        window_key = f"{key}:{int(time.time() // period)}"
        count = self.memory_storage.get(window_key, 0)
        if count >= limit:
            return False
        self.memory_storage[window_key] = count + 1
        return True

    def _check_rate_limit_token_bucket(self, key, limit, period):
        """Check rate limit using token bucket strategy."""
        tokens_per_second = limit / period

        if self.backend in ("redis", "cache"):
            cache_key = f"rate_limit_bucket:{key}"

            if self.backend == "cache":
                bucket_data = cache.get(cache_key, None)
                current_time = time.time()

                if bucket_data is None:
                    # Initialize bucket
                    bucket_data = {
                        "tokens": limit,
                        "last_update": current_time,
                    }
                else:
                    # Update tokens
                    time_passed = current_time - bucket_data["last_update"]
                    new_tokens = time_passed * tokens_per_second
                    bucket_data["tokens"] = min(
                        limit, bucket_data["tokens"] + new_tokens
                    )
                    bucket_data["last_update"] = current_time

                if bucket_data["tokens"] < 1:
                    cache.set(cache_key, bucket_data, period)
                    return False

                bucket_data["tokens"] -= 1
                cache.set(cache_key, bucket_data, period)
                return True

        return True

    def _check_rate_limit(self, key, limit, period):
        """Check rate limit based on configured strategy."""
        if self.strategy == "sliding_window":
            return self._check_rate_limit_sliding_window(key, limit, period)
        elif self.strategy == "fixed_window":
            return self._check_rate_limit_fixed_window(key, limit, period)
        elif self.strategy == "token_bucket":
            return self._check_rate_limit_token_bucket(key, limit, period)
        else:
            return self._check_rate_limit_sliding_window(key, limit, period)

    def process_request(self, request):
        """Check rate limit before processing request."""
        if not self.enabled:
            return None

        # Skip rate limiting for certain paths
        skip_paths = self.rate_config.get(
            "SKIP_PATHS",
            [
                "/admin/",
                "/static/",
                "/media/",
                "/__debug__/",
            ],
        )

        for skip_path in skip_paths:
            if request.path.startswith(skip_path):
                return None

        # Get rate limit key and type
        key, limit_type = self._get_rate_limit_key(request)

        # Get applicable limit
        limit, period = self._get_limit_for_request(request, limit_type)

        # Check rate limit
        if not self._check_rate_limit(key, limit, period):
            # Rate limit exceeded
            retry_after = period

            # Log rate limit violation
            if settings.DEBUG:
                print(f"Rate limit exceeded for {key}: {limit}/{period}s")

            # Return 429 response
            response_data = {
                "error": "Rate limit exceeded",
                "message": f"Too many requests. Please try again in {retry_after} seconds.",
                "retry_after": retry_after,
            }

            response = JsonResponse(response_data, status=429)
            response["Retry-After"] = str(retry_after)
            response["X-RateLimit-Limit"] = str(limit)
            response["X-RateLimit-Remaining"] = "0"
            response["X-RateLimit-Reset"] = str(int(time.time() + retry_after))

            return response

        # Add rate limit headers to request for later use
        request._rate_limit_info = {
            "limit": limit,
            "period": period,
            "key": key,
        }

        return None

    def process_response(self, request, response):
        """Add rate limit headers to response."""
        if hasattr(request, "_rate_limit_info"):
            info = request._rate_limit_info
            response["X-RateLimit-Limit"] = str(info["limit"])
            # Calculate remaining (approximate)
            response["X-RateLimit-Period"] = str(info["period"])

        return response
