"""
Test endpoints for security module verification
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from app.security.decorators import (
    rate_limit,
    validate_input,
    secure_response,
    audit_log,
)


@require_http_methods(["GET"])
def health_check(request):
    """Simple health check endpoint."""
    return JsonResponse(
        {"status": "ok", "message": "API is running with security module enabled"}
    )


@rate_limit("5/m", key="ip")
@require_http_methods(["GET"])
def rate_limit_endpoint(request):
    """Test rate limiting - allows only 5 requests per minute."""
    return JsonResponse(
        {
            "status": "success",
            "message": "Rate limit test endpoint - max 5 requests per minute",
        }
    )


@validate_input(
    {
        "email": "email",
        "age": ("integer", {"min": 18, "max": 120}),
    }
)
@csrf_exempt  # Only for testing
@require_http_methods(["POST"])
def validation_endpoint(request):
    """Test input validation."""
    return JsonResponse(
        {
            "status": "success",
            "message": "Input validation passed",
            "validated_data": request.validated_data,
        }
    )


@secure_response(exclude_fields=["password", "secret"])
@require_http_methods(["GET"])
def secure_response_endpoint(request):
    """Test response sanitization."""
    # This simulates getting user data
    data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "secretpassword123",  # This will be excluded
        "secret": "api_key_12345",  # This will be excluded
        "bio": "<script>alert('xss')</script>Hello",  # This will be escaped
    }
    return data


@audit_log("test_security_check", log_request=True)
@require_http_methods(["GET"])
def audit_log_endpoint(request):
    """Test audit logging."""
    return JsonResponse(
        {"status": "success", "message": "This request has been logged for audit"}
    )


# Test suspicious patterns (this will be blocked)
@require_http_methods(["GET"])
def sql_injection_endpoint(request):
    """This endpoint helps test SQL injection detection."""
    query = request.GET.get("query", "")
    return JsonResponse({"status": "success", "message": f"Your query: {query}"})


@require_http_methods(["GET"])
def headers_endpoint(request):
    """Check security headers."""
    headers = {
        "Content-Security-Policy": "Present"
        if "Content-Security-Policy" in request.META
        else "Missing",
        "X-Frame-Options": request.META.get("HTTP_X_FRAME_OPTIONS", "Not set"),
        "X-Content-Type-Options": request.META.get(
            "HTTP_X_CONTENT_TYPE_OPTIONS", "Not set"
        ),
        "Referrer-Policy": request.META.get("HTTP_REFERRER_POLICY", "Not set"),
    }
    return JsonResponse({"status": "success", "security_headers": headers})
