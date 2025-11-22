"""
URL configuration for security testing endpoints
"""

from django.urls import path
from . import test_security

urlpatterns = [
    path("health/", test_security.health_check, name="health_check"),
    path("test-rate-limit/", test_security.rate_limit_endpoint, name="test_rate_limit"),
    path("test-validation/", test_security.validation_endpoint, name="test_validation"),
    path(
        "test-secure-response/",
        test_security.secure_response_endpoint,
        name="test_secure_response",
    ),
    path("test-audit/", test_security.audit_log_endpoint, name="test_audit_log"),
    path("test-sql/", test_security.sql_injection_endpoint, name="test_sql_injection"),
    path("test-headers/", test_security.headers_endpoint, name="test_headers"),
]
