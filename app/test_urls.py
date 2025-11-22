"""
URL configuration for security testing endpoints
"""

from django.urls import path
from . import test_security

urlpatterns = [
    path("health/", test_security.health_check, name="health_check"),
    path("test-rate-limit/", test_security.test_rate_limit, name="test_rate_limit"),
    path("test-validation/", test_security.test_validation, name="test_validation"),
    path(
        "test-secure-response/",
        test_security.test_secure_response,
        name="test_secure_response",
    ),
    path("test-audit/", test_security.test_audit_log, name="test_audit_log"),
    path("test-sql/", test_security.test_sql_injection, name="test_sql_injection"),
    path("test-headers/", test_security.test_headers, name="test_headers"),
]
