"""
Middleware for session security.

Enforces session timeouts, IP binding, session fixation protection,
and detects potential session hijacking.
"""

from typing import Optional

from django.contrib import auth
from django.contrib.auth.signals import user_logged_in
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from ..conf import get_setting
from ..signals import session_expired, session_hijacking_detected
from ..utils.ip import get_client_ip


class SessionSecurityMiddleware:
    """
    Middleware to enforce session security policies.

    Features:
    - Absolute session timeout (max session duration)
    - Inactivity timeout (session expires after inactivity)
    - Session rotation on login (prevent session fixation)
    - IP binding (detect IP changes)
    - User agent binding (optional, detect UA changes)
    """

    def __init__(self, get_response):
        self.get_response = get_response

        # Load configuration
        session_config = get_setting("SESSION_SECURITY", {})
        self.absolute_timeout = session_config.get("ABSOLUTE_TIMEOUT", 28800)  # 8 hours
        self.inactivity_timeout = session_config.get(
            "INACTIVITY_TIMEOUT", 3600
        )  # 1 hour
        self.rotate_on_login = session_config.get("ROTATE_ON_LOGIN", True)
        self.bind_to_ip = session_config.get("BIND_TO_IP", True)
        self.bind_to_user_agent = session_config.get("BIND_TO_USER_AGENT", False)

        # Register signal handler for session rotation
        if self.rotate_on_login:
            user_logged_in.connect(
                self._rotate_session_on_login, dispatch_uid="security_rotate_session"
            )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request and check session security."""
        # Skip for non-authenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Check session validity
        session_valid, reason = self._check_session_validity(request)

        if not session_valid:
            # Log out user and clear session
            session_key = request.session.session_key
            auth.logout(request)

            # Send signal
            session_expired.send(
                sender=self.__class__,
                user=request.user,
                session_key=session_key,
                reason=reason,
            )

            # You might want to redirect to login or return an error response
            # For now, just continue with logged-out user

        # Update last activity timestamp
        self._update_activity(request)

        response = self.get_response(request)
        return response

    def _check_session_validity(
        self, request: HttpRequest
    ) -> tuple[bool, Optional[str]]:
        """
        Check if session is still valid.

        Returns:
            Tuple of (is_valid, reason_if_invalid)
        """
        session = request.session

        # Check absolute timeout
        if self.absolute_timeout:
            session_start = session.get("_security_session_start")
            if session_start:
                session_age = timezone.now() - timezone.datetime.fromisoformat(
                    session_start
                )
                if session_age.total_seconds() > self.absolute_timeout:
                    return False, "absolute_timeout"

        # Check inactivity timeout
        if self.inactivity_timeout:
            last_activity = session.get("_security_last_activity")
            if last_activity:
                inactive_duration = timezone.now() - timezone.datetime.fromisoformat(
                    last_activity
                )
                if inactive_duration.total_seconds() > self.inactivity_timeout:
                    return False, "inactivity_timeout"

        # Check IP binding
        if self.bind_to_ip:
            stored_ip = session.get("_security_ip")
            current_ip = get_client_ip(request)

            if stored_ip and stored_ip != current_ip:
                # Potential session hijacking
                session_hijacking_detected.send(
                    sender=self.__class__,
                    user=request.user,
                    session_key=request.session.session_key,
                    reason="ip_mismatch",
                )
                return False, "ip_mismatch"

        # Check User-Agent binding
        if self.bind_to_user_agent:
            stored_ua = session.get("_security_user_agent")
            current_ua = request.META.get("HTTP_USER_AGENT", "")

            if stored_ua and stored_ua != current_ua:
                # Potential session hijacking
                session_hijacking_detected.send(
                    sender=self.__class__,
                    user=request.user,
                    session_key=request.session.session_key,
                    reason="user_agent_mismatch",
                )
                return False, "user_agent_mismatch"

        return True, None

    def _update_activity(self, request: HttpRequest):
        """Update session activity timestamps."""
        session = request.session

        # Set session start time if not set
        if "_security_session_start" not in session:
            session["_security_session_start"] = timezone.now().isoformat()

        # Update last activity
        session["_security_last_activity"] = timezone.now().isoformat()

        # Store IP if binding is enabled
        if self.bind_to_ip and "_security_ip" not in session:
            session["_security_ip"] = get_client_ip(request)

        # Store User-Agent if binding is enabled
        if self.bind_to_user_agent and "_security_user_agent" not in session:
            session["_security_user_agent"] = request.META.get("HTTP_USER_AGENT", "")

    def _rotate_session_on_login(self, sender, request, user, **kwargs):
        """
        Rotate session ID on login to prevent session fixation attacks.

        This is called via signal when user logs in.
        """
        if hasattr(request, "session"):
            # Cycle the session key
            request.session.cycle_key()

            # Initialize security tracking for new session
            request.session["_security_session_start"] = timezone.now().isoformat()
            request.session["_security_last_activity"] = timezone.now().isoformat()

            if self.bind_to_ip:
                request.session["_security_ip"] = get_client_ip(request)

            if self.bind_to_user_agent:
                request.session["_security_user_agent"] = request.META.get(
                    "HTTP_USER_AGENT", ""
                )


def get_session_info(request: HttpRequest) -> dict:
    """
    Get information about the current session security status.

    Args:
        request: The HttpRequest object

    Returns:
        Dictionary with session security information
    """
    if not hasattr(request, "session"):
        return {}

    session = request.session
    session_config = get_setting("SESSION_SECURITY", {})

    info = {
        "authenticated": request.user.is_authenticated,
        "session_key": session.session_key,
    }

    if request.user.is_authenticated:
        session_start = session.get("_security_session_start")
        last_activity = session.get("_security_last_activity")

        if session_start:
            session_start_dt = timezone.datetime.fromisoformat(session_start)
            session_age = timezone.now() - session_start_dt
            absolute_timeout = session_config.get("ABSOLUTE_TIMEOUT", 28800)

            info.update(
                {
                    "session_start": session_start,
                    "session_age_seconds": int(session_age.total_seconds()),
                    "time_until_absolute_timeout": max(
                        0, absolute_timeout - int(session_age.total_seconds())
                    ),
                }
            )

        if last_activity:
            last_activity_dt = timezone.datetime.fromisoformat(last_activity)
            inactive_duration = timezone.now() - last_activity_dt
            inactivity_timeout = session_config.get("INACTIVITY_TIMEOUT", 3600)

            info.update(
                {
                    "last_activity": last_activity,
                    "inactive_seconds": int(inactive_duration.total_seconds()),
                    "time_until_inactivity_timeout": max(
                        0, inactivity_timeout - int(inactive_duration.total_seconds())
                    ),
                }
            )

        info.update(
            {
                "ip_address": session.get("_security_ip"),
                "user_agent": session.get("_security_user_agent"),
            }
        )

    return info
