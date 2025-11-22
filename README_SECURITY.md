# Django Security Module Documentation

## Overview

This Django Security Module provides comprehensive security configurations and middlewares for Django projects. It implements industry best practices for:
- Secure configuration defaults
- HTTP security headers (CSP, HSTS, etc.)
- Rate limiting
- Request size limits
- Suspicious pattern detection
- Input validation and output sanitization
- Security decorators for view-level controls

## Features

### 1. Secure Configuration by Default
- SSL/TLS enforcement
- Secure cookie settings
- HSTS (HTTP Strict Transport Security)
- Password validation
- Session security

### 2. Security Middlewares
- **SecurityHeadersMiddleware**: Adds security headers (CSP, X-Frame-Options, etc.)
- **RateLimitingMiddleware**: Prevents abuse with configurable rate limits
- **RequestSizeLimitMiddleware**: Enforces request size limits
- **SuspiciousPatternsMiddleware**: Detects and blocks malicious patterns

### 3. Input/Output Protection
- Input validation against SQL injection and XSS
- HTML sanitization using bleach
- Safe JSON encoding
- Mass assignment protection

### 4. Security Decorators
- `@rate_limit`: Per-view rate limiting
- `@csp_update`: Modify CSP for specific views
- `@validate_input`: Request validation
- `@secure_response`: Response sanitization
- `@audit_log`: Security audit logging

## Installation

### 1. Install Dependencies

```bash
# Using uv
uv add django djangorestframework python-decouple redis bleach

# Or using pip
pip install django djangorestframework python-decouple redis bleach
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Django Settings
SECRET_KEY=your-secure-key-minimum-50-characters
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Redis (optional, for advanced rate limiting)
REDIS_URL=redis://localhost:6379/0

# Security Settings
CSRF_TRUSTED_ORIGINS=https://yourdomain.com
SECURITY_RISK_PROFILE=moderate  # Options: strict, moderate, relaxed
```

### 3. Update Django Settings

The security module is already integrated in `app/settings.py`. The configuration automatically:
- Applies secure defaults based on DEBUG mode
- Adds security middleware
- Configures security headers

## Configuration

### Risk Profiles

The module provides three pre-configured risk profiles:

#### Strict (Production)
- Maximum security
- HTTPS enforced
- No inline scripts/styles in CSP
- 30-minute sessions
- Aggressive rate limiting

```python
# In settings.py or .env
SECURITY_RISK_PROFILE=strict
```

#### Moderate (Staging)
- Balanced security and usability
- HTTPS recommended
- Limited inline scripts allowed
- 2-hour sessions
- Standard rate limiting

```python
SECURITY_RISK_PROFILE=moderate
```

#### Relaxed (Development)
- Development-friendly
- HTTPS not required
- Permissive CSP
- 24-hour sessions
- Minimal rate limiting

```python
SECURITY_RISK_PROFILE=relaxed
```

### Custom Configuration

Override specific settings in `settings.py`:

```python
DJANGO_SEC = {
    'ENABLE_SECURITY_HEADERS': True,
    'ENABLE_RATE_LIMITING': True,
    'CSP_POLICY': 'strict',

    'RATE_LIMITING': {
        'DEFAULT_LIMITS': {
            'anonymous': '50/h',
            'authenticated': '500/h',
        },
        'ENDPOINT_LIMITS': {
            '/api/sensitive/': '10/h',
        },
    },
}
```

## Usage Examples

### 1. Security Decorators

```python
from app.security.decorators import (
    rate_limit, validate_input, secure_response, csp_update
)

# Rate limiting
@rate_limit('10/m', key='user')
def api_endpoint(request):
    return JsonResponse({'status': 'ok'})

# Input validation
@validate_input({
    'email': 'email',
    'age': ('integer', {'min': 18, 'max': 120}),
    'role': ('choice', {'choices': ['user', 'admin']}),
})
def create_user(request):
    # request.validated_data contains clean data
    return JsonResponse(request.validated_data)

# Response sanitization
@secure_response(exclude_fields=['password', 'token'])
def get_user_profile(request):
    user_data = get_user_data()
    return user_data

# CSP modification
@csp_update(script_src="'self' https://trusted-cdn.com")
def view_with_external_script(request):
    return render(request, 'template.html')
```

### 2. Input Validation

```python
from app.security.validation import validate_input, InputValidator

# Validate dictionary
data = {
    'email': 'user@example.com',
    'phone': '+1234567890',
    'website': 'https://example.com',
}

schema = {
    'email': 'email',
    'phone': 'phone',
    'website': 'url',
}

validated = validate_input(data, schema)

# Direct validation
validator = InputValidator()
clean_email = validator.validate_email('user@example.com')
clean_phone = validator.validate_phone('+1234567890')
```

### 3. Output Sanitization

```python
from app.security.validation import (
    sanitize_html, escape_html, safe_json_response
)

# HTML sanitization
user_content = '<script>alert("XSS")</script><p>Hello</p>'
safe_content = sanitize_html(user_content)
# Result: '<p>Hello</p>'

# JSON response sanitization
response_data = {
    'name': 'John Doe',
    'password': 'secret123',  # Will be removed
    'bio': '<script>alert("xss")</script>Hello',
}
safe_data = safe_json_response(response_data)
# password field removed, bio field escaped
```

### 4. Using with Django REST Framework

```python
from rest_framework.views import APIView
from app.security.validation import SecureSerializer
from app.security.decorators import rate_limit, secure_response

class UserAPIView(APIView):
    @rate_limit('100/h')
    @secure_response(exclude_fields=['password'])
    def get(self, request):
        # Your logic here
        return Response(data)

# Secure serializer with built-in validation
class UserSerializer(SecureSerializer):
    email = serializers.EmailField()
    name = serializers.CharField(max_length=100)

    class Meta:
        model = User
        fields = ['email', 'name']
```

## Security Checks

Run Django security checks:

```bash
# Run all security checks
python manage.py check --tag security

# Run all checks including security
python manage.py check
```

The module checks for:
- DEBUG mode in production
- SECRET_KEY configuration
- ALLOWED_HOSTS settings
- CSRF configuration
- SSL/HTTPS settings
- Security headers
- Password validators

## Monitoring and Logging

### Rate Limit Monitoring

Rate limit violations are logged and include:
- Client IP address
- Endpoint accessed
- Limit exceeded details

### Suspicious Pattern Detection

The middleware logs:
- Detected patterns (SQL injection, XSS, etc.)
- Source IP addresses
- Auto-blocking events

### Audit Logging

Use the audit decorator for sensitive operations:

```python
@audit_log('user_login', log_request=True)
def login_view(request):
    # Login logic
    return response
```

## Extending the Module

### Adding Custom Validators

```python
# In your app
from app.security.validation import InputValidator

class CustomValidator(InputValidator):
    @classmethod
    def validate_custom_field(cls, value):
        # Your validation logic
        if not is_valid(value):
            raise ValueError("Invalid value")
        return clean_value
```

### Custom Middleware

```python
from app.security.middleware import SecurityMiddleware

class CustomSecurityMiddleware(SecurityMiddleware):
    def process_request(self, request):
        # Your custom logic
        return super().process_request(request)
```

### Custom CSP Policies

```python
# In settings.py
DJANGO_SEC['CSP_POLICY'] = 'custom'
DJANGO_SEC['CSP_DIRECTIVES'] = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline' https://trusted.com",
    'style-src': "'self' 'unsafe-inline'",
}
```

## Production Deployment

### Pre-deployment Checklist

1. **Environment Variables**
   - [ ] SECRET_KEY is unique and secure (50+ characters)
   - [ ] DEBUG = False
   - [ ] ALLOWED_HOSTS configured
   - [ ] CSRF_TRUSTED_ORIGINS set

2. **Security Profile**
   - [ ] SECURITY_RISK_PROFILE = 'strict' or 'moderate'
   - [ ] Redis configured for rate limiting (optional but recommended)

3. **HTTPS Configuration**
   - [ ] SSL certificate installed
   - [ ] SECURE_SSL_REDIRECT = True
   - [ ] HSTS enabled

4. **Run Security Checks**
   ```bash
   python manage.py check --deploy --tag security
   ```

### Nginx Configuration Example

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Security headers (some are set by Django)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

### Common Issues

1. **Rate limiting not working**
   - Check Redis connection: `redis-cli ping`
   - Verify REDIS_URL in settings
   - Check ENABLE_RATE_LIMITING is True

2. **CSP blocking resources**
   - Check browser console for CSP violations
   - Use CSP_REPORT_ONLY mode for testing
   - Adjust CSP_POLICY or use @csp_update decorator

3. **Legitimate requests blocked**
   - Check suspicious patterns logs
   - Adjust SUSPICIOUS_THRESHOLD
   - Whitelist specific IPs if needed

4. **Session expires too quickly**
   - Adjust SESSION_COOKIE_AGE
   - Check SESSION_SAVE_EVERY_REQUEST setting

### Debug Mode

Enable detailed logging:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'security.log',
        },
    },
    'loggers': {
        'security': {
            'handlers': ['file'],
            'level': 'INFO',
        },
    },
}
```

## Performance Impact

The security module has minimal performance impact:
- Middleware adds < 5ms per request
- Rate limiting uses efficient caching
- Pattern matching is optimized with compiled regex
- HTML sanitization is lazy (only when needed)

## License

This security module is provided as part of the project. Use and modify as needed for your Django applications.

## Support

For issues or questions:
1. Check this documentation
2. Review the code in `/app/security/`
3. Run security checks: `python manage.py check --tag security`

## Version

Current Version: 1.0.0
Compatible with: Django 5.2+