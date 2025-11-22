"""
Unit tests for Security Middleware
"""

import pytest
from django.test import RequestFactory, override_settings
from django.http import HttpResponse
from app.security.middleware.suspicious_patterns import SuspiciousPatternsMiddleware
from app.security.middleware.rate_limiting import RateLimitingMiddleware
from app.security.middleware.request_size_limit import RequestSizeLimitMiddleware


class TestSuspiciousPatternsMiddleware:
    """Test SuspiciousPatternsMiddleware"""

    @pytest.fixture
    def factory(self):
        return RequestFactory()

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
            "SUSPICIOUS_THRESHOLD": 5,
            "BLOCK_DURATION": 3600,
        }
    )
    def test_sql_injection_blocked(self, factory):
        """Test that SQL injection attempts are blocked"""
        # Create middleware after override_settings is applied
        middleware = SuspiciousPatternsMiddleware(lambda r: HttpResponse("OK"))

        request = factory.get("/test/?query='; DROP TABLE users; --'")
        response = middleware.process_request(request)

        assert response is not None
        assert response.status_code == 403
        assert b"Forbidden" in response.content

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    def test_xss_blocked(self, factory):
        """Test that XSS attempts are blocked"""
        middleware = SuspiciousPatternsMiddleware(lambda r: HttpResponse("OK"))
        request = factory.get("/test/?query=<script>alert('xss')</script>")
        response = middleware.process_request(request)

        assert response is not None
        assert response.status_code == 403

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    def test_path_traversal_blocked(self, factory):
        """Test that path traversal attempts are blocked"""
        middleware = SuspiciousPatternsMiddleware(lambda r: HttpResponse("OK"))
        request = factory.get("/test/?file=../../etc/passwd")
        response = middleware.process_request(request)

        assert response is not None
        assert response.status_code == 403

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    def test_suspicious_user_agent_blocked(self, factory):
        """Test that suspicious user agents are blocked"""
        middleware = SuspiciousPatternsMiddleware(lambda r: HttpResponse("OK"))
        request = factory.get("/test/", HTTP_USER_AGENT="sqlmap/1.0")
        response = middleware.process_request(request)

        assert response is not None
        assert response.status_code == 403

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": False,
        }
    )
    def test_disabled_middleware(self, factory):
        """Test that disabled middleware doesn't block"""
        middleware = SuspiciousPatternsMiddleware(lambda r: HttpResponse("OK"))
        request = factory.get("/test/?query='; DROP TABLE users; --'")
        response = middleware.process_request(request)

        assert response is None

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    @pytest.mark.parametrize(
        "malicious_query",
        [
            "'; DROP TABLE users; --'",
            "' OR 1=1--",
            "' UNION SELECT * FROM users--",
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "../../etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
    )
    def test_various_attacks_blocked(self, factory, malicious_query):
        """Test that various attack patterns are blocked"""
        middleware = SuspiciousPatternsMiddleware(lambda r: HttpResponse("OK"))
        request = factory.get(f"/test/?query={malicious_query}")
        response = middleware.process_request(request)

        assert response is not None
        assert response.status_code == 403


class TestRateLimitingMiddleware:
    """Test RateLimitingMiddleware"""

    @pytest.fixture
    def factory(self):
        return RequestFactory()

    @override_settings(
        DJANGO_SEC={
            "ENABLE_RATE_LIMITING": True,
            "RATE_LIMITING": {
                "BACKEND": "memory",
                "DEFAULT_LIMITS": {
                    "anonymous": "5/m",
                    "authenticated": "100/m",
                },
            },
        }
    )
    def test_rate_limiting_enforced(self, factory):
        """Test that rate limiting is enforced"""
        middleware = RateLimitingMiddleware(lambda r: HttpResponse("OK"))

        # Make 6 requests (limit is 5/minute)
        responses = []
        for _ in range(6):
            request = factory.get("/test/")
            response = middleware.process_request(request)
            responses.append(response)

        # First 5 should pass (None response)
        assert all(r is None for r in responses[:5])

        # 6th should be rate limited
        assert responses[5] is not None
        assert responses[5].status_code == 429

    @override_settings(
        DJANGO_SEC={
            "ENABLE_RATE_LIMITING": False,
        }
    )
    def test_disabled_rate_limiting(self, factory):
        """Test that disabled rate limiting doesn't limit"""
        middleware = RateLimitingMiddleware(lambda r: HttpResponse("OK"))

        # Make multiple requests
        for _ in range(10):
            request = factory.get("/test/")
            response = middleware.process_request(request)
            assert response is None

    @override_settings(
        DJANGO_SEC={
            "ENABLE_RATE_LIMITING": True,
            "RATE_LIMITING": {
                "SKIP_PATHS": ["/admin/", "/static/"],
            },
        }
    )
    def test_skip_paths(self, factory):
        """Test that certain paths skip rate limiting"""
        middleware = RateLimitingMiddleware(lambda r: HttpResponse("OK"))

        # Make many requests to admin path
        for _ in range(20):
            request = factory.get("/admin/")
            response = middleware.process_request(request)
            assert response is None  # Should not be rate limited


class TestRequestSizeLimitMiddleware:
    """Test RequestSizeLimitMiddleware"""

    @pytest.fixture
    def factory(self):
        return RequestFactory()

    @override_settings(
        DJANGO_SEC={
            "ENABLE_REQUEST_SIZE_LIMIT": True,
            "REQUEST_SIZE_LIMIT": 100,  # 100 bytes for testing
        }
    )
    def test_request_size_limit_enforced(self, factory):
        """Test that request size limit is enforced"""
        middleware = RequestSizeLimitMiddleware(lambda r: HttpResponse("OK"))

        # Create a large request body (200 bytes)
        large_data = "x" * 200
        request = factory.post("/test/", data=large_data, content_type="text/plain")
        response = middleware.process_request(request)

        assert response is not None
        assert response.status_code == 413

    @override_settings(
        DJANGO_SEC={
            "ENABLE_REQUEST_SIZE_LIMIT": True,
            "REQUEST_SIZE_LIMIT": 1000,
        }
    )
    def test_small_request_allowed(self, factory):
        """Test that small requests are allowed"""
        middleware = RequestSizeLimitMiddleware(lambda r: HttpResponse("OK"))

        small_data = "x" * 50
        request = factory.post("/test/", data=small_data, content_type="text/plain")
        response = middleware.process_request(request)

        assert response is None

    @override_settings(
        DJANGO_SEC={
            "ENABLE_REQUEST_SIZE_LIMIT": False,
        }
    )
    def test_disabled_size_limit(self, factory):
        """Test that disabled size limit doesn't restrict"""
        middleware = RequestSizeLimitMiddleware(lambda r: HttpResponse("OK"))

        large_data = "x" * 10000
        request = factory.post("/test/", data=large_data, content_type="text/plain")
        response = middleware.process_request(request)

        assert response is None
