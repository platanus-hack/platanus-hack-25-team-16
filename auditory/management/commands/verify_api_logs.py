"""
Management command to verify the integrity of API request logs.
"""

import sys
from django.core.management.base import BaseCommand

from auditory.api.models import APIRequestLog
from auditory.registry import security_state


class Command(BaseCommand):
    help = "Verify the cryptographic integrity of API request logs"

    def add_arguments(self, parser):
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Show detailed information about each log entry",
        )
        parser.add_argument(
            "--limit",
            type=int,
            help="Limit verification to the most recent N logs",
        )
        parser.add_argument(
            "--fix",
            action="store_true",
            help="Attempt to fix broken chain by recalculating hashes (dangerous!)",
        )

    def handle(self, *args, **options):
        verbose = options.get("verbose", False)
        limit = options.get("limit")  # noqa: F841
        fix = options.get("fix", False)

        if fix:
            self.stdout.write(
                self.style.WARNING(
                    "WARNING: Fix mode will recalculate hashes. This should only be done "
                    "if you understand the implications for audit integrity."
                )
            )
            confirm = input("Are you sure you want to continue? (yes/no): ")
            if confirm.lower() != "yes":
                self.stdout.write(self.style.ERROR("Operation cancelled."))
                return

        # Get the backend
        backend = security_state.get_backend()

        if not hasattr(backend, "verify_api_chain"):
            self.stdout.write(
                self.style.ERROR(
                    "Current backend does not support API log verification."
                )
            )
            sys.exit(1)

        # Count total logs
        total_logs = APIRequestLog.objects.count()
        self.stdout.write(f"Total API logs in database: {total_logs}")

        if total_logs == 0:
            self.stdout.write(self.style.WARNING("No API logs found to verify."))
            return

        # Verify the chain
        self.stdout.write("Verifying hash chain integrity...")
        result = backend.verify_api_chain()

        # Display results
        if result["ok"]:
            self.stdout.write(
                self.style.SUCCESS("✓ Hash chain integrity verified successfully!")
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"  Checked {result['checked']} log entries - all valid."
                )
            )
        else:
            mismatches = result["mismatches"]
            self.stdout.write(self.style.ERROR("✗ Hash chain integrity compromised!"))
            self.stdout.write(
                self.style.ERROR(
                    f"  Found {len(mismatches)} corrupted entries out of {result['checked']} checked."
                )
            )

            if verbose:
                self.stdout.write("\nCorrupted entries:")
                for event_id in mismatches[:10]:  # Show first 10
                    try:
                        log = APIRequestLog.objects.get(event_id=event_id)
                        self.stdout.write(
                            f"  - {log.timestamp} | {log.http_method} {log.endpoint} | "
                            f"User: {log.username or 'anonymous'} | Status: {log.response_status}"
                        )
                    except APIRequestLog.DoesNotExist:
                        self.stdout.write(f"  - Event {event_id} (not found)")

                if len(mismatches) > 10:
                    self.stdout.write(f"  ... and {len(mismatches) - 10} more")

            # Offer to fix if requested
            if fix and mismatches:
                self._fix_chain(mismatches)

        # Additional statistics
        if verbose:
            self._show_statistics()

    def _fix_chain(self, mismatches):
        """
        Attempt to fix the hash chain by recalculating hashes.
        WARNING: This breaks audit integrity and should only be used in emergencies.
        """
        self.stdout.write("\nAttempting to fix hash chain...")

        from auditory.audit.backends.base import canonical_json
        import hashlib
        import hmac
        from django.conf import settings
        import os

        # Get HMAC key
        key_env = "AUDIT_HASH_KEY"
        key = os.environ.get(key_env) or getattr(settings, "SECRET_KEY", "")
        key_bytes = key.encode("utf-8")

        # Recalculate all hashes in order
        logs = APIRequestLog.objects.order_by("timestamp")
        prev_hash = "0" * 64
        fixed_count = 0

        for log in logs:
            # Calculate what the hash should be
            canonical_payload = canonical_json(
                {
                    "correlation_id": log.correlation_id,
                    "endpoint": log.endpoint,
                    "http_method": log.http_method,
                    "request_path": log.request_path,
                    "response_status": log.response_status,
                    "user_id": log.user_id,
                    "ip_address": log.ip_address,
                    "timestamp": log.timestamp.isoformat(),
                }
            )

            content = (
                f"{prev_hash}|{canonical_payload}|{log.timestamp.isoformat()}".encode(
                    "utf-8"
                )
            )
            expected_hash = hmac.new(key_bytes, content, hashlib.sha256).hexdigest()

            # Update if different
            if log.hash_current != expected_hash or log.hash_prev != prev_hash:
                log.hash_prev = prev_hash
                log.hash_current = expected_hash
                log.save(update_fields=["hash_prev", "hash_current"])
                fixed_count += 1

            prev_hash = expected_hash

        self.stdout.write(self.style.SUCCESS(f"Fixed {fixed_count} log entries."))

    def _show_statistics(self):
        """Show additional statistics about the API logs."""
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write("API Log Statistics:")

        # Time range
        first_log = APIRequestLog.objects.order_by("timestamp").first()
        last_log = APIRequestLog.objects.order_by("-timestamp").first()

        if first_log and last_log:
            self.stdout.write(
                f"  Date range: {first_log.timestamp} to {last_log.timestamp}"
            )

        # Status code distribution
        from django.db.models import Count

        status_dist = (
            APIRequestLog.objects.values("response_status")
            .annotate(count=Count("response_status"))
            .order_by("-count")[:10]
        )

        if status_dist:
            self.stdout.write("\n  Top response status codes:")
            for item in status_dist:
                status = item["response_status"]
                count = item["count"]
                self.stdout.write(f"    {status}: {count} requests")

        # Top endpoints
        endpoint_dist = (
            APIRequestLog.objects.values("endpoint")
            .annotate(count=Count("endpoint"))
            .order_by("-count")[:5]
        )

        if endpoint_dist:
            self.stdout.write("\n  Top 5 endpoints:")
            for item in endpoint_dist:
                endpoint = item["endpoint"]
                count = item["count"]
                self.stdout.write(f"    {endpoint}: {count} requests")

        # Authentication methods
        auth_dist = (
            APIRequestLog.objects.exclude(auth_method__isnull=True)
            .values("auth_method")
            .annotate(count=Count("auth_method"))
            .order_by("-count")
        )

        if auth_dist:
            self.stdout.write("\n  Authentication methods used:")
            for item in auth_dist:
                method = item["auth_method"] or "anonymous"
                count = item["count"]
                self.stdout.write(f"    {method}: {count} requests")

        # Average response time
        from django.db.models import Avg

        avg_time = APIRequestLog.objects.aggregate(avg=Avg("response_time_ms"))["avg"]

        if avg_time:
            self.stdout.write(f"\n  Average response time: {avg_time:.2f} ms")

        self.stdout.write("=" * 50)
