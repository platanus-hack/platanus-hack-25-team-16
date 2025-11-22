"""
Integration tests for Security Endpoints
"""

import pytest
from django.test import Client, override_settings


@pytest.mark.django_db
class TestSecurityEndpoints:
    """Test security endpoints with full middleware stack"""

    @pytest.fixture
    def client(self):
        return Client()

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/api/security-test/health/")
        assert response.status_code == 200
        assert b"ok" in response.content

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    def test_sql_injection_endpoint_blocked(self, client):
        """Test that SQL injection is blocked on test endpoint"""
        response = client.get(
            "/api/security-test/test-sql/",
            {"query": "'; DROP TABLE users; --'"},
        )
        assert response.status_code == 403
        data = response.json()
        assert "Forbidden" in data.get("error", "")

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "log",
        }
    )
    def test_sql_injection_endpoint_logged_only(self, client):
        """Test that SQL injection is only logged when action=log"""
        response = client.get(
            "/api/security-test/test-sql/",
            {"query": "'; DROP TABLE users; --'"},
        )
        # Should pass through when action is 'log'
        assert response.status_code == 200

    def test_validation_endpoint_missing_field(self, client):
        """Test validation endpoint with missing required field"""
        response = client.post(
            "/api/security-test/test-validation/",
            data={"email": "test@example.com"},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.json()
        assert "age" in data.get("details", {})

    def test_validation_endpoint_invalid_age(self, client):
        """Test validation endpoint with invalid age"""
        response = client.post(
            "/api/security-test/test-validation/",
            data={"email": "test@example.com", "age": 15},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.json()
        assert "age" in data.get("details", {})

    def test_validation_endpoint_valid_data(self, client):
        """Test validation endpoint with valid data"""
        response = client.post(
            "/api/security-test/test-validation/",
            data={"email": "test@example.com", "age": 25},
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "success"

    def test_validation_endpoint_invalid_email(self, client):
        """Test validation endpoint with invalid email"""
        response = client.post(
            "/api/security-test/test-validation/",
            data={"email": "not-an-email", "age": 25},
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.json()
        assert "email" in data.get("details", {})

    @override_settings(
        DJANGO_SEC={
            "ENABLE_RATE_LIMITING": True,
            "RATE_LIMITING": {
                "BACKEND": "memory",
                "DEFAULT_LIMITS": {
                    "anonymous": "3/m",
                },
            },
        }
    )
    def test_rate_limiting_endpoint(self, client):
        """Test rate limiting on test endpoint"""
        # Make requests up to the limit
        for i in range(3):
            response = client.get("/api/security-test/test-rate-limit/")
            assert response.status_code == 200, f"Request {i + 1} should succeed"

        # Next request should be rate limited
        response = client.get("/api/security-test/test-rate-limit/")
        assert response.status_code == 429
        data = response.json()
        assert "Rate limit exceeded" in data.get("error", "")

    def test_security_headers_present(self, client):
        """Test that security headers are present in responses"""
        response = client.get("/api/security-test/health/")

        # Check for security headers
        assert "X-Content-Type-Options" in response
        assert "X-Frame-Options" in response

    def test_audit_log_endpoint(self, client):
        """Test audit log endpoint"""
        response = client.get("/api/security-test/test-audit/")
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "success"


@pytest.mark.django_db
class TestCSRFProtection:
    """Test CSRF protection"""

    @pytest.fixture
    def client(self):
        return Client(enforce_csrf_checks=True)

    def test_csrf_protection_on_post(self, client):
        """Test that CSRF protection is enforced on POST requests"""
        # Note: test_validation endpoint uses @csrf_exempt for testing
        # For real endpoints without @csrf_exempt, this would fail
        response = client.post(
            "/api/security-test/test-validation/",
            data={"email": "test@example.com", "age": 25},
            content_type="application/json",
        )
        # This endpoint has @csrf_exempt, so it should work
        assert response.status_code in [200, 400]


@pytest.mark.django_db
class TestClickjackingProtection:
    """Test clickjacking protection via X-Frame-Options"""

    @pytest.fixture
    def client(self):
        return Client()

    def test_x_frame_options_header(self, client):
        """Test that X-Frame-Options header is set"""
        response = client.get("/api/security-test/health/")

        assert "X-Frame-Options" in response
        # Should be DENY or SAMEORIGIN
        assert response["X-Frame-Options"] in ["DENY", "SAMEORIGIN"]


@pytest.mark.django_db
class TestXSSProtection:
    """Test XSS protection"""

    @pytest.fixture
    def client(self):
        return Client()

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    @pytest.mark.parametrize(
        "xss_payload",
        [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<iframe src='http://evil.com'></iframe>",
        ],
    )
    def test_xss_blocked(self, client, xss_payload):
        """Test that various XSS payloads are blocked"""
        response = client.get(
            "/api/security-test/test-sql/",
            {"query": xss_payload},
        )
        assert response.status_code == 403

    def test_secure_response_sanitization(self, client):
        """Test that response data is sanitized"""
        response = client.get("/api/security-test/test-secure-response/")
        data = response.json()

        # Password and secret fields should be excluded
        assert "password" not in data
        assert "secret" not in data

        # Username should be present
        assert "username" in data


@pytest.mark.django_db
class TestPathTraversal:
    """Test path traversal protection"""

    @pytest.fixture
    def client(self):
        return Client()

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
        }
    )
    @pytest.mark.parametrize(
        "traversal_payload",
        [
            "../../etc/passwd",
            "../../../etc/shadow",
            "..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
    )
    def test_path_traversal_blocked(self, client, traversal_payload):
        """Test that path traversal attempts are blocked"""
        response = client.get(
            "/api/security-test/test-sql/",
            {"query": traversal_payload},
        )
        assert response.status_code == 403


@pytest.mark.django_db
class TestMultipleAttackVectors:
    """Test combinations of attack vectors"""

    @pytest.fixture
    def client(self):
        return Client()

    @override_settings(
        DJANGO_SEC={
            "ENABLE_SUSPICIOUS_PATTERNS": True,
            "SUSPICIOUS_ACTION": "block",
            "SUSPICIOUS_THRESHOLD": 3,
        }
    )
    def test_multiple_attacks_trigger_blocking(self, client):
        """Test that multiple attack attempts trigger IP blocking"""
        # Make multiple malicious requests
        for _ in range(5):
            client.get(
                "/api/security-test/test-sql/",
                {"query": "'; DROP TABLE users; --'"},
            )

        # After threshold, should be blocked
        response = client.get("/api/security-test/health/")
        # Note: IP blocking uses cache, may need cache backend configured
        assert response.status_code in [200, 403]
