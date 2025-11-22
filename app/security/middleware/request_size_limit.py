"""
Request Size Limit Middleware

Enforces request size limits to prevent resource exhaustion attacks.
"""

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse


class RequestSizeLimitMiddleware(MiddlewareMixin):
    """
    Middleware to enforce request size limits.

    Prevents large request bodies that could cause DoS.
    Configurable per endpoint.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

        # Get configuration
        self.config = getattr(settings, "DJANGO_SEC", {})
        self.enabled = self.config.get("ENABLE_REQUEST_SIZE_LIMIT", True)

        # Default limit (10 MB)
        self.default_limit = self.config.get("REQUEST_SIZE_LIMIT", 10 * 1024 * 1024)

        # Endpoint-specific limits
        self.endpoint_limits = self.config.get(
            "REQUEST_SIZE_LIMITS",
            {
                "/api/upload/": 500 * 1024 * 1024,  # 500 MB for uploads
                "/api/import/": 100 * 1024 * 1024,  # 100 MB for imports
                "/api/avatar/": 5 * 1024 * 1024,  # 5 MB for avatars
            },
        )

    def _get_request_size(self, request):
        """Get the size of the request body."""
        content_length = request.META.get("CONTENT_LENGTH")

        if content_length:
            try:
                return int(content_length)
            except (ValueError, TypeError):
                return 0

        # If no Content-Length header, estimate from body
        if hasattr(request, "body"):
            return len(request.body)

        return 0

    def _get_limit_for_path(self, path):
        """Get the size limit for a specific path."""
        # Check exact matches first
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]

        # Check prefix matches
        for endpoint, limit in self.endpoint_limits.items():
            if path.startswith(endpoint):
                return limit

        return self.default_limit

    def _format_size(self, size_bytes):
        """Format size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    def process_request(self, request):
        """Check request size before processing."""
        if not self.enabled:
            return None

        # Skip for certain paths
        skip_paths = ["/admin/", "/static/", "/media/"]
        for skip_path in skip_paths:
            if request.path.startswith(skip_path):
                return None

        # Get request size
        request_size = self._get_request_size(request)
        if request_size == 0:
            return None

        # Get limit for this path
        limit = self._get_limit_for_path(request.path)

        # Check if request exceeds limit
        if request_size > limit:
            # Log violation
            if settings.DEBUG:
                print(
                    f"Request size limit exceeded: {self._format_size(request_size)} > {self._format_size(limit)}"
                )

            # Return 413 response
            response_data = {
                "error": "Request entity too large",
                "message": f"Request size {self._format_size(request_size)} exceeds limit of {self._format_size(limit)}",
                "request_size": request_size,
                "size_limit": limit,
            }

            response = JsonResponse(response_data, status=413)
            response["Content-Length"] = str(len(response.content))
            return response

        # Add size info to request for logging
        request._request_size = request_size

        return None


class ChunkedUploadMiddleware(MiddlewareMixin):
    """
    Middleware to handle chunked uploads.

    Supports resumable uploads for large files.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

        self.config = getattr(settings, "DJANGO_SEC", {})
        self.enabled = self.config.get("ENABLE_CHUNKED_UPLOAD", False)

        # Chunked upload settings
        self.chunk_size = self.config.get("CHUNK_SIZE", 5 * 1024 * 1024)  # 5 MB chunks
        self.temp_dir = self.config.get("CHUNK_TEMP_DIR", "/tmp/uploads/")

    def process_request(self, request):
        """Process chunked upload requests."""
        if not self.enabled:
            return None

        # Check for chunked upload headers
        content_range = request.META.get("HTTP_CONTENT_RANGE")
        if not content_range:
            return None

        # Parse content range
        try:
            range_header = content_range.replace("bytes ", "")
            range_parts = range_header.split("/")
            byte_range = range_parts[0].split("-")
            start_byte = int(byte_range[0])
            end_byte = int(byte_range[1])
            total_size = int(range_parts[1]) if range_parts[1] != "*" else None

            # Store chunk info in request
            request._chunk_info = {
                "start": start_byte,
                "end": end_byte,
                "total": total_size,
                "is_chunked": True,
            }

            # Validate chunk
            if end_byte - start_byte > self.chunk_size:
                return JsonResponse(
                    {
                        "error": "Chunk too large",
                        "message": f"Chunk size exceeds {self._format_size(self.chunk_size)}",
                    },
                    status=400,
                )

        except (ValueError, IndexError):
            return JsonResponse(
                {
                    "error": "Invalid Content-Range header",
                },
                status=400,
            )

        return None

    def _format_size(self, size_bytes):
        """Format size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
