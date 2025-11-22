"""
Management command to generate ISO27001 compliance reports.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from auditory.compliance.reports import ISO27001Reporter


class Command(BaseCommand):
    help = 'Generate ISO27001 compliance report based on audit logs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to include in the report (default: 30)',
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['json', 'html', 'both'],
            default='json',
            help='Output format for the report',
        )
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path (default: iso27001_report_<timestamp>.<format>)',
        )
        parser.add_argument(
            '--email',
            type=str,
            help='Email address to send the report to',
        )
        parser.add_argument(
            '--print',
            action='store_true',
            help='Print report summary to console',
        )

    def handle(self, *args, **options):
        days = options['days']
        output_format = options['format']
        output_path = options.get('output')
        email = options.get('email')
        print_summary = options.get('print', False)

        # Calculate date range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)

        self.stdout.write(
            f"Generating ISO27001 compliance report for the last {days} days..."
        )
        self.stdout.write(
            f"Period: {start_date.date()} to {end_date.date()}"
        )

        # Generate report
        reporter = ISO27001Reporter(start_date=start_date, end_date=end_date)
        report = reporter.generate()

        # Save report
        saved_files = []

        if output_format in ['json', 'both']:
            json_file = self._save_json_report(report, output_path)
            saved_files.append(json_file)
            self.stdout.write(
                self.style.SUCCESS(f"✓ JSON report saved to: {json_file}")
            )

        if output_format in ['html', 'both']:
            html_file = self._save_html_report(report, reporter, output_path)
            saved_files.append(html_file)
            self.stdout.write(
                self.style.SUCCESS(f"✓ HTML report saved to: {html_file}")
            )

        # Print summary if requested
        if print_summary:
            self._print_summary(report)

        # Send email if requested
        if email:
            self._send_email_report(email, report, saved_files)

        # Final summary
        self.stdout.write(
            self.style.SUCCESS(
                f"\n✓ Compliance report generated successfully!"
            )
        )
        self.stdout.write(
            f"  Compliance Status: {report['executive_summary']['compliance_status']}"
        )
        self.stdout.write(
            f"  Risk Level: {report['executive_summary']['risk_level']}"
        )
        self.stdout.write(
            f"  Total Events Logged: {report['executive_summary']['total_events_logged']:,}"
        )

    def _save_json_report(self, report, output_path):
        """Save report as JSON file."""
        if output_path and not output_path.endswith('.json'):
            output_path = f"{output_path}.json"

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"iso27001_report_{timestamp}.json"

        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return output_path

    def _save_html_report(self, report, reporter, output_path):
        """Save report as HTML file."""
        if output_path and not output_path.endswith('.html'):
            output_path = f"{output_path}.html"

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"iso27001_report_{timestamp}.html"

        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        html_content = reporter.to_html(report)
        with open(output_path, 'w') as f:
            f.write(html_content)

        return output_path

    def _print_summary(self, report):
        """Print report summary to console."""
        self.stdout.write("\n" + "="*60)
        self.stdout.write("COMPLIANCE REPORT SUMMARY")
        self.stdout.write("="*60)

        # Executive Summary
        summary = report['executive_summary']
        self.stdout.write("\nExecutive Summary:")
        self.stdout.write(f"  Status: {summary['compliance_status']}")
        self.stdout.write(f"  Risk Level: {summary['risk_level']}")
        self.stdout.write(f"  Coverage: {summary['coverage_percentage']:.1f}%")
        self.stdout.write(f"  Total Events: {summary['total_events_logged']:,}")
        self.stdout.write(f"  Security Incidents: {summary['security_incidents']}")
        self.stdout.write(f"  Failed Auth: {summary['failed_authentications']}")

        # Control Implementation
        self.stdout.write("\nControl Implementation Status:")
        controls = report['control_mappings']
        for control_id, control in controls.items():
            status_style = self.style.SUCCESS if control['status'] == 'IMPLEMENTED' else self.style.WARNING
            self.stdout.write(
                f"  {control_id} - {control['title']}: " +
                status_style(control['status'])
            )

        # API Metrics
        if 'api_metrics' in report and report['api_metrics']:
            api = report['api_metrics']
            self.stdout.write(f"\nAPI Metrics:")
            self.stdout.write(f"  Total Requests: {api['total_requests']:,}")
            self.stdout.write(f"  Success Rate: {api['success_rate']}")
            if api['performance']:
                self.stdout.write(f"  Avg Response Time: {api['performance']['avg_response_time']:.2f}ms")

        # Security Events
        if 'security_events' in report:
            security = report['security_events']
            self.stdout.write(f"\nSecurity Events:")
            self.stdout.write(f"  Failed Auth: {security['failed_authentications']['total']}")
            if security['failed_authentications']['suspicious_ips']:
                self.stdout.write("  Suspicious IPs:")
                for ip_info in security['failed_authentications']['suspicious_ips'][:3]:
                    self.stdout.write(
                        f"    - {ip_info['ip']}: {ip_info['attempts']} attempts"
                    )

        # Data Integrity
        integrity = report['data_integrity']
        self.stdout.write(f"\nData Integrity:")
        self.stdout.write(
            f"  Audit Logs: " +
            (self.style.SUCCESS('VALID') if integrity['audit_logs']['status'] == 'VALID'
             else self.style.ERROR('COMPROMISED'))
        )
        self.stdout.write(
            f"  API Logs: " +
            (self.style.SUCCESS('VALID') if integrity['api_logs']['status'] == 'VALID'
             else self.style.ERROR('COMPROMISED'))
        )

        # Recommendations
        if report['recommendations']:
            self.stdout.write("\nKey Recommendations:")
            for i, rec in enumerate(report['recommendations'][:5], 1):
                self.stdout.write(f"  {i}. {rec}")

        self.stdout.write("="*60 + "\n")

    def _send_email_report(self, email, report, attachments):
        """Send report via email (placeholder implementation)."""
        # In production, implement actual email sending
        # using Django's email backend
        self.stdout.write(
            self.style.WARNING(
                f"\nEmail functionality not implemented. Would send to: {email}"
            )
        )
        self.stdout.write(f"  Attachments: {', '.join(attachments)}")

        # Example implementation:
        # from django.core.mail import EmailMessage
        #
        # subject = f"ISO27001 Compliance Report - {report['metadata']['generated_at']}"
        # body = f"Please find attached the compliance report for {report['metadata']['reporting_period']['start']} to {report['metadata']['reporting_period']['end']}"
        #
        # email_msg = EmailMessage(
        #     subject=subject,
        #     body=body,
        #     from_email='compliance@example.com',
        #     to=[email],
        # )
        #
        # for attachment in attachments:
        #     email_msg.attach_file(attachment)
        #
        # email_msg.send()