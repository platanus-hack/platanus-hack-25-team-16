"""
ISO27001 Compliance Report Generator.
"""

import json
from datetime import timedelta
from typing import Dict, Any, List

from django.utils import timezone
from django.db.models import Count, Avg, Max, Min

from auditory.audit.models import AuditLogEntry
from auditory.api.models import APIRequestLog


class ISO27001Reporter:
    """
    Generate comprehensive ISO27001 compliance reports based on audit logs.
    """

    def __init__(self, start_date=None, end_date=None):
        """
        Initialize reporter with optional date range.

        Args:
            start_date: Start of reporting period (default: 30 days ago)
            end_date: End of reporting period (default: now)
        """
        self.end_date = end_date or timezone.now()
        self.start_date = start_date or (self.end_date - timedelta(days=30))

    def generate(self) -> Dict[str, Any]:
        """
        Generate complete ISO27001 compliance report.

        Returns:
            Dictionary containing all compliance metrics and evidence
        """
        report = {
            'metadata': self._get_metadata(),
            'executive_summary': self._generate_executive_summary(),
            'control_mappings': self._map_controls(),
            'audit_metrics': self._get_audit_metrics(),
            'api_metrics': self._get_api_metrics(),
            'security_events': self._get_security_events(),
            'data_integrity': self._verify_data_integrity(),
            'recommendations': self._generate_recommendations(),
        }

        return report

    def _get_metadata(self) -> Dict[str, Any]:
        """Get report metadata."""
        return {
            'report_id': timezone.now().strftime('%Y%m%d_%H%M%S'),
            'generated_at': timezone.now().isoformat(),
            'reporting_period': {
                'start': self.start_date.isoformat(),
                'end': self.end_date.isoformat(),
                'days': (self.end_date - self.start_date).days,
            },
            'standard': 'ISO/IEC 27001:2022',
            'report_version': '1.0',
        }

    def _generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary of compliance status."""
        # Count total events
        audit_logs = AuditLogEntry.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        ).count()

        api_logs = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        ).count()

        # Check for security issues
        security_issues = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date),
            response_status__gte=500
        ).count()

        failed_auth = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date),
            response_status=401
        ).count()

        return {
            'compliance_status': 'COMPLIANT' if security_issues < 100 else 'NEEDS_REVIEW',
            'total_events_logged': audit_logs + api_logs,
            'audit_logs': audit_logs,
            'api_requests': api_logs,
            'security_incidents': security_issues,
            'failed_authentications': failed_auth,
            'coverage_percentage': self._calculate_coverage(),
            'risk_level': self._assess_risk_level(security_issues, failed_auth),
        }

    def _map_controls(self) -> Dict[str, Dict[str, Any]]:
        """Map ISO27001 controls to implementation evidence."""
        controls = {}

        # A.8.15 - Logging
        controls['A.8.15'] = {
            'title': 'Logging',
            'status': 'IMPLEMENTED',
            'evidence': {
                'total_logs': AuditLogEntry.objects.count() + APIRequestLog.objects.count(),
                'log_types': ['audit_logs', 'api_logs'],
                'retention_days': 180,
                'fields_captured': [
                    'timestamp', 'user_id', 'ip_address',
                    'action', 'resource', 'status'
                ],
            },
            'implementation_details': 'Comprehensive logging via auditory module with hash chain integrity',
        }

        # A.5.33 - Protection of records
        controls['A.5.33'] = {
            'title': 'Protection of records',
            'status': 'IMPLEMENTED',
            'evidence': {
                'integrity_mechanism': 'HMAC-SHA256 hash chain',
                'tamper_detection': 'Cryptographic verification',
                'immutability': True,
                'verification_command': 'python manage.py verify_api_logs',
            },
            'implementation_details': 'Hash chain ensures tamper-evident logging',
        }

        # A.8.16 - Monitoring activities
        controls['A.8.16'] = {
            'title': 'Monitoring activities',
            'status': 'IMPLEMENTED',
            'evidence': {
                'real_time_monitoring': True,
                'api_requests_logged': APIRequestLog.objects.count(),
                'model_changes_logged': AuditLogEntry.objects.count(),
                'alert_mechanisms': 'Management commands for verification',
            },
            'implementation_details': 'Real-time monitoring of all API requests and model changes',
        }

        # A.8.9 - Configuration management
        controls['A.8.9'] = {
            'title': 'Configuration management',
            'status': 'IMPLEMENTED',
            'evidence': {
                'configuration_file': 'SECURITY_CONFIG in settings.py',
                'validation': 'Startup validation in AppConfig',
                'environment_aware': True,
            },
            'implementation_details': 'Centralized security configuration with validation',
        }

        # A.8.23 - Web filtering
        controls['A.8.23'] = {
            'title': 'Web filtering',
            'status': 'PARTIALLY_IMPLEMENTED',
            'evidence': {
                'input_sanitization': True,
                'pii_masking': True,
                'output_encoding': True,
            },
            'implementation_details': 'PII masking and input sanitization implemented',
            'gaps': ['Content Security Policy could be stricter'],
        }

        # A.8.28 - Secure coding
        controls['A.8.28'] = {
            'title': 'Secure coding',
            'status': 'IMPLEMENTED',
            'evidence': {
                'sensitive_data_handling': 'PII masking policy',
                'password_protection': 'Never logged in plain text',
                'error_handling': 'Sanitized error messages',
            },
            'implementation_details': 'Secure coding practices enforced through policies',
        }

        return controls

    def _get_audit_metrics(self) -> Dict[str, Any]:
        """Get metrics from audit logs (model changes)."""
        queryset = AuditLogEntry.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        )

        # Actions distribution
        actions = queryset.values('action').annotate(
            count=Count('action')
        ).order_by('-count')

        # Most modified models
        models = queryset.values('app_label', 'model').annotate(
            count=Count('id')
        ).order_by('-count')[:10]

        # Active users
        active_users = queryset.exclude(
            actor__isnull=True
        ).values('actor', 'actor_label').annotate(
            actions=Count('id')
        ).order_by('-actions')[:10]

        return {
            'total_changes': queryset.count(),
            'actions': {item['action']: item['count'] for item in actions},
            'top_models': [
                f"{item['app_label']}.{item['model']}: {item['count']}"
                for item in models
            ],
            'active_users': [
                {
                    'user': item['actor_label'] or item['actor'],
                    'actions': item['actions']
                }
                for item in active_users
            ],
        }

    def _get_api_metrics(self) -> Dict[str, Any]:
        """Get metrics from API request logs."""
        queryset = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        )

        # Response status distribution
        status_dist = queryset.values('response_status').annotate(
            count=Count('response_status')
        ).order_by('response_status')

        # Calculate percentages
        total_requests = queryset.count()
        success_rate = 0
        if total_requests > 0:
            success_count = queryset.filter(
                response_status__gte=200,
                response_status__lt=300
            ).count()
            success_rate = (success_count / total_requests) * 100

        # Performance metrics
        performance = queryset.aggregate(
            avg_response_time=Avg('response_time_ms'),
            max_response_time=Max('response_time_ms'),
            min_response_time=Min('response_time_ms'),
        )

        # Top endpoints
        endpoints = queryset.values('endpoint').annotate(
            requests=Count('endpoint'),
            avg_time=Avg('response_time_ms')
        ).order_by('-requests')[:10]

        # Authentication methods
        auth_methods = queryset.exclude(
            auth_method__isnull=True
        ).values('auth_method').annotate(
            count=Count('auth_method')
        ).order_by('-count')

        return {
            'total_requests': total_requests,
            'success_rate': f"{success_rate:.2f}%",
            'status_codes': {
                str(item['response_status']): item['count']
                for item in status_dist
            },
            'performance': performance,
            'top_endpoints': [
                {
                    'endpoint': item['endpoint'],
                    'requests': item['requests'],
                    'avg_time_ms': round(item['avg_time'], 2) if item['avg_time'] else 0
                }
                for item in endpoints
            ],
            'auth_methods': {
                item['auth_method'] or 'anonymous': item['count']
                for item in auth_methods
            },
        }

    def _get_security_events(self) -> Dict[str, Any]:
        """Identify and categorize security events."""
        queryset = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        )

        # Failed authentications
        failed_auth = queryset.filter(response_status=401)

        # Suspicious IPs (multiple failed auth attempts)
        suspicious_ips = failed_auth.values('ip_address').annotate(
            attempts=Count('ip_address')
        ).filter(attempts__gte=5).order_by('-attempts')

        # Server errors (potential security issues)
        server_errors = queryset.filter(response_status__gte=500)

        # Rate limited requests
        rate_limited = queryset.filter(throttled=True)

        # Forbidden access attempts
        forbidden = queryset.filter(response_status=403)

        return {
            'failed_authentications': {
                'total': failed_auth.count(),
                'unique_ips': failed_auth.values('ip_address').distinct().count(),
                'suspicious_ips': [
                    {
                        'ip': item['ip_address'],
                        'attempts': item['attempts']
                    }
                    for item in suspicious_ips
                ],
            },
            'server_errors': {
                'total': server_errors.count(),
                'endpoints': server_errors.values('endpoint').annotate(
                    count=Count('endpoint')
                ).order_by('-count')[:5],
            },
            'rate_limiting': {
                'throttled_requests': rate_limited.count(),
            },
            'access_violations': {
                'forbidden_attempts': forbidden.count(),
            },
        }

    def _verify_data_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of logged data."""
        from auditory.registry import security_state

        backend = security_state.get_backend()

        # Verify audit log chain
        audit_result = {'status': 'NOT_VERIFIED', 'details': 'Backend does not support verification'}
        if hasattr(backend, 'verify_chain'):
            result = backend.verify_chain()
            audit_result = {
                'status': 'VALID' if result['ok'] else 'COMPROMISED',
                'checked': result['checked'],
                'issues': result.get('mismatches', []),
            }

        # Verify API log chain
        api_result = {'status': 'NOT_VERIFIED', 'details': 'Backend does not support verification'}
        if hasattr(backend, 'verify_api_chain'):
            result = backend.verify_api_chain()
            api_result = {
                'status': 'VALID' if result['ok'] else 'COMPROMISED',
                'checked': result['checked'],
                'issues': result.get('mismatches', []),
            }

        return {
            'audit_logs': audit_result,
            'api_logs': api_result,
            'overall_status': 'VALID' if (
                audit_result.get('status') == 'VALID' and
                api_result.get('status') == 'VALID'
            ) else 'NEEDS_REVIEW',
        }

    def _calculate_coverage(self) -> float:
        """Calculate audit coverage percentage."""
        # This is a simplified calculation
        # In production, you'd check against actual models/endpoints
        covered_items = 0
        total_items = 10  # Example total

        # Check if we have audit logs
        if AuditLogEntry.objects.exists():
            covered_items += 5

        # Check if we have API logs
        if APIRequestLog.objects.exists():
            covered_items += 5

        return (covered_items / total_items) * 100

    def _assess_risk_level(self, security_issues: int, failed_auth: int) -> str:
        """Assess overall risk level based on security metrics."""
        if security_issues > 100 or failed_auth > 500:
            return 'HIGH'
        elif security_issues > 50 or failed_auth > 100:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Check for high error rates
        error_rate = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date),
            response_status__gte=500
        ).count()

        total = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        ).count()

        if total > 0 and (error_rate / total) > 0.05:
            recommendations.append(
                "High server error rate detected (>5%). Investigate and fix root causes."
            )

        # Check for suspicious activity
        suspicious = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date),
            response_status=401
        ).values('ip_address').annotate(
            attempts=Count('ip_address')
        ).filter(attempts__gte=10)

        if suspicious.exists():
            recommendations.append(
                f"Suspicious activity detected from {suspicious.count()} IP addresses. "
                "Consider implementing rate limiting or IP blocking."
            )

        # Check average response time
        avg_response = APIRequestLog.objects.filter(
            timestamp__range=(self.start_date, self.end_date)
        ).aggregate(avg=Avg('response_time_ms'))['avg']

        if avg_response and avg_response > 1000:
            recommendations.append(
                f"High average response time ({avg_response:.0f}ms). "
                "Consider performance optimization."
            )

        # Always include best practices
        recommendations.extend([
            "Regularly review and update access control policies",
            "Conduct periodic security audits and penetration testing",
            "Maintain up-to-date documentation of security procedures",
            "Ensure all staff receive security awareness training",
        ])

        return recommendations

    def to_json(self, report: Dict[str, Any]) -> str:
        """Convert report to JSON string."""
        return json.dumps(report, indent=2, default=str)

    def to_html(self, report: Dict[str, Any]) -> str:
        """Convert report to HTML format."""
        # This is a simple implementation
        # In production, use a proper template engine
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ISO27001 Compliance Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; border-bottom: 1px solid #ddd; }}
                .metric {{ margin: 10px 0; }}
                .status-valid {{ color: green; }}
                .status-invalid {{ color: red; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>ISO27001 Compliance Report</h1>
            <p>Generated: {report['metadata']['generated_at']}</p>
            <p>Period: {report['metadata']['reporting_period']['start']} to
               {report['metadata']['reporting_period']['end']}</p>

            <h2>Executive Summary</h2>
            <div class="metric">Compliance Status: {report['executive_summary']['compliance_status']}</div>
            <div class="metric">Total Events: {report['executive_summary']['total_events_logged']}</div>
            <div class="metric">Risk Level: {report['executive_summary']['risk_level']}</div>

            <h2>Control Implementation</h2>
            <table>
                <tr>
                    <th>Control</th>
                    <th>Title</th>
                    <th>Status</th>
                </tr>
        """

        for control_id, control in report['control_mappings'].items():
            html += f"""
                <tr>
                    <td>{control_id}</td>
                    <td>{control['title']}</td>
                    <td class="status-{'valid' if control['status'] == 'IMPLEMENTED' else 'invalid'}">
                        {control['status']}
                    </td>
                </tr>
            """

        html += """
            </table>
        </body>
        </html>
        """

        return html