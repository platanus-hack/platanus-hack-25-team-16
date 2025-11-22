"""
Signed URL generation and validation for secure file access.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from django.conf import settings
from django.http import HttpResponse, Http404
from django.core.exceptions import PermissionDenied
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from django.utils import timezone

logger = logging.getLogger(__name__)


class SignedURLManager:
    """
    Manages generation and validation of signed URLs for temporary file access.

    Implements time-limited, cryptographically signed URLs that can optionally
    be bound to specific IPs and include permission scopes.

    ISO 27001 Controls:
    - A.9.4.1: Information access restriction
    - A.13.2.1: Information transfer policies and procedures
    """

    def __init__(self):
        """Initialize the URL manager with signing configuration."""
        # Get secret key for signing
        secret_key = settings.SECRET_KEY

        # Initialize serializer with salt for additional security
        self.serializer = URLSafeTimedSerializer(
            secret_key, salt="encrypted-file-download"
        )

        # Get configuration
        django_sec = getattr(settings, "DJANGO_SEC", {})
        self.config = django_sec.get("ENCRYPTED_FILES", {})
        self.signed_urls_config = self.config.get("SIGNED_URLS", {})

        # Default settings
        self.default_expiry = self.signed_urls_config.get("DEFAULT_EXPIRY", 3600)
        self.bind_to_ip_default = self.signed_urls_config.get("BIND_TO_IP", False)
        self.include_permissions = self.signed_urls_config.get(
            "INCLUDE_PERMISSIONS", True
        )

        logger.debug("SignedURLManager initialized with configuration")

    def generate_url(
        self,
        file_path: str,
        expires_in: Optional[int] = None,
        permissions: Optional[List[str]] = None,
        bind_to_ip: Optional[bool] = None,
        user_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a signed URL for temporary file access.

        Args:
            file_path: Path to the file
            expires_in: Expiry time in seconds (None = use default)
            permissions: List of permissions (e.g., ['read', 'download'])
            bind_to_ip: Whether to bind URL to requester's IP
            user_id: User ID to associate with the URL
            metadata: Additional metadata to include in the token

        Returns:
            Complete signed URL as string
        """
        if expires_in is None:
            expires_in = self.default_expiry

        if permissions is None:
            permissions = ["read"]

        if bind_to_ip is None:
            bind_to_ip = self.bind_to_ip_default

        # Build token data
        token_data = {
            "path": file_path,
            "created_at": timezone.now().isoformat(),
            "expires_in": expires_in,
        }

        # Add optional data
        if self.include_permissions:
            token_data["permissions"] = permissions

        if user_id:
            token_data["user_id"] = user_id

        if bind_to_ip:
            # Get current IP if available
            ip = self._get_current_ip()
            if ip:
                token_data["ip"] = ip

        if metadata:
            token_data["metadata"] = metadata

        # Generate signed token
        try:
            token = self.serializer.dumps(token_data)

            # Generate URL
            # Note: In a real implementation, you'd need to configure URL routing
            # For now, we'll return a conceptual URL structure
            base_url = self._get_base_url()
            download_endpoint = self.signed_urls_config.get(
                "DOWNLOAD_ENDPOINT", "/api/secure-download/"
            )

            url = f"{base_url}{download_endpoint}?token={token}"

            logger.info(
                f"Generated signed URL for file: {file_path}, expires in: {expires_in}s"
            )

            return url

        except Exception as e:
            logger.error(f"Error generating signed URL: {e}")
            raise

    def validate_token(
        self, token: str, request_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate a signed token and return its data.

        Args:
            token: The signed token to validate
            request_ip: IP address of the request (for IP binding validation)

        Returns:
            Dictionary containing token data

        Raises:
            PermissionDenied: If token is invalid, expired, or fails validation
        """
        try:
            # Decode token with max_age validation
            data = self.serializer.loads(token, max_age=None)

            # Manual expiry check (since we store expires_in in the token)
            created_at = timezone.datetime.fromisoformat(data["created_at"])
            expires_in = data.get("expires_in", self.default_expiry)

            if timezone.now() > created_at + timezone.timedelta(seconds=expires_in):
                raise SignatureExpired("Token has expired")

            # Validate IP binding if enabled
            if "ip" in data and request_ip:
                if data["ip"] != request_ip:
                    logger.warning(
                        f"IP mismatch for token. Expected: {data['ip']}, Got: {request_ip}"
                    )
                    raise PermissionDenied("Invalid IP address for this download link")

            logger.info(f"Successfully validated token for file: {data.get('path')}")

            return data

        except SignatureExpired:
            logger.warning("Attempted to use expired token")
            raise PermissionDenied("This download link has expired")

        except BadSignature:
            logger.warning("Attempted to use invalid token")
            raise PermissionDenied("Invalid download link")

        except Exception as e:
            logger.error(f"Error validating token: {e}")
            raise PermissionDenied("Invalid download link")

    def serve_file(self, token: str, request_ip: Optional[str] = None) -> HttpResponse:
        """
        Validate token and serve the decrypted file.

        Args:
            token: The signed token
            request_ip: Request IP address

        Returns:
            HttpResponse with decrypted file content

        Raises:
            Http404: If file not found or access denied
        """
        try:
            # Validate token
            token_data = self.validate_token(token, request_ip)

            file_path = token_data["path"]
            permissions = token_data.get("permissions", ["read"])

            # Check if download is allowed
            if "download" not in permissions and "read" not in permissions:
                raise PermissionDenied("No download permission for this file")

            # Import here to avoid circular imports
            from .encrypted_file_field import EncryptedFileField
            from .models import FileAccessLog

            # Create a field instance for decryption
            # In a real implementation, you'd get this from the model
            field = EncryptedFileField()

            # Decrypt file
            decrypted_content = field.decrypt_file(file_path)

            # Create response
            response = HttpResponse(
                decrypted_content, content_type="application/octet-stream"
            )

            # Set headers for download
            filename = os.path.basename(file_path)
            # Remove .enc extension if present
            if filename.endswith(".enc"):
                filename = filename[:-4]

            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            response["Content-Length"] = len(decrypted_content)

            # Log successful download
            FileAccessLog.objects.create(
                file_path=file_path,
                action="download_via_signed_url",
                user_id=token_data.get("user_id"),
                ip_address=request_ip or "0.0.0.0",
                status="success",
                metadata={
                    "permissions": permissions,
                    "token_metadata": token_data.get("metadata", {}),
                },
            )

            logger.info(f"Successfully served file via signed URL: {file_path}")

            return response

        except PermissionDenied:
            raise Http404("File not found or access denied")

        except Exception as e:
            logger.error(f"Error serving file: {e}")
            raise Http404("File not found")

    def revoke_url(self, token: str) -> bool:
        """
        Revoke a signed URL (for future implementation).

        In a production system, this would add the token to a revocation list
        checked during validation.

        Args:
            token: Token to revoke

        Returns:
            True if revoked successfully
        """
        # This would typically store the token in a cache/database
        # for checking during validation
        logger.info("Token revocation requested (not implemented)")
        return True

    def _get_current_ip(self) -> Optional[str]:
        """
        Get current request IP if available.

        This is a placeholder - in real usage, this would get the IP
        from the current request context.
        """
        try:
            from app.security.utils.helpers import get_client_ip

            return get_client_ip()
        except:  # noqa: E722
            return None

    def _get_base_url(self) -> str:
        """Get base URL for the application."""
        # Try to get from settings
        site_url = getattr(settings, "SITE_URL", None)
        if site_url:
            return site_url.rstrip("/")

        # Try to construct from allowed hosts
        allowed_hosts = getattr(settings, "ALLOWED_HOSTS", [])
        if allowed_hosts and allowed_hosts[0] != "*":
            protocol = "https" if not settings.DEBUG else "http"
            return f"{protocol}://{allowed_hosts[0]}"

        # Default for development
        return "http://localhost:8000"


class SignedURLView:
    """
    View mixin for handling signed URL downloads.

    This can be used in Django views to serve files via signed URLs.
    """

    def download_with_signed_url(self, request):
        """
        Handle file download via signed URL.

        Args:
            request: Django HTTP request

        Returns:
            HTTP response with file or error
        """
        token = request.GET.get("token")

        if not token:
            raise Http404("Invalid download link")

        # Get client IP
        client_ip = self._get_client_ip(request)

        # Create manager and serve file
        manager = SignedURLManager()
        return manager.serve_file(token, client_ip)

    def _get_client_ip(self, request) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "0.0.0.0")
        return ip
