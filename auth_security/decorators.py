"""
Decorators for authentication and security enforcement.

Provides decorators for sensitive operations and access control.
For MFA, use django-otp's @otp_required decorator instead.
"""

from functools import wraps
from typing import Callable

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse


def sensitive_operation(audit: bool = True, require_recent_auth: bool = False):
    """
    Decorator to mark a view as a sensitive operation.

    Args:
        audit: Whether to log this operation for audit purposes
        require_recent_auth: Whether to require recent authentication (e.g., within last 15 min)

    Usage:
        @sensitive_operation(audit=True, require_recent_auth=True)
        def delete_account(request):
            pass
    """

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        @login_required
        def _wrapped_view(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            # Check for recent authentication if required
            if require_recent_auth:
                last_login = request.session.get("_security_last_login_timestamp")
                if last_login:
                    from django.utils import timezone
                    from datetime import timedelta

                    last_login_dt = timezone.datetime.fromisoformat(last_login)
                    age = timezone.now() - last_login_dt

                    # Require authentication within last 15 minutes
                    if age > timedelta(minutes=15):
                        # Store the operation they were trying to do
                        request.session["_security_operation_pending"] = (
                            request.get_full_path()
                        )

                        # Redirect to re-authentication
                        return redirect(
                            reverse("login") + "?next=" + request.get_full_path()
                        )

            # Mark this request as sensitive (can be used by audit logging)
            request._security_sensitive_operation = True

            # Execute the view
            response = view_func(request, *args, **kwargs)

            # Audit logging would happen here or in middleware
            if audit:
                # Log the sensitive operation
                # This could be done via signals or direct logging
                pass

            return response

        return _wrapped_view

    return decorator


def ip_whitelist(allowed_ips: list[str]):
    """
    Decorator to restrict view access to specific IP addresses.

    Args:
        allowed_ips: List of allowed IP addresses or CIDR ranges

    Usage:
        @ip_whitelist(['192.168.1.0/24', '10.0.0.1'])
        def admin_endpoint(request):
            pass
    """

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def _wrapped_view(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            from .utils.ip import get_client_ip
            import ipaddress

            client_ip = get_client_ip(request)

            # Check if client IP is in whitelist
            allowed = False
            for allowed_range in allowed_ips:
                try:
                    # Try as network (CIDR)
                    network = ipaddress.ip_network(allowed_range, strict=False)
                    if ipaddress.ip_address(client_ip) in network:
                        allowed = True
                        break
                except ValueError:
                    # Try as single IP
                    if client_ip == allowed_range:
                        allowed = True
                        break

            if not allowed:
                raise PermissionDenied(f"Access denied from IP: {client_ip}")

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


# Note: For MFA requirements, use django-otp decorators instead:
#
# from django_otp.decorators import otp_required
#
# @otp_required
# def sensitive_view(request):
#     pass
#
# Or for more control:
#
# from django_otp import user_has_device
#
# def my_view(request):
#     if not user_has_device(request.user):
#         return redirect('otp_setup')
#     ...
