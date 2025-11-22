# Django Security Library - Especificación Completa

## Visión General

Librería Django/DRF que proporciona protecciones automáticas para cumplir con ISO 27001 y OWASP Top 10, mediante middlewares, campos especiales, validaciones, y herramientas de auditoría.

## Estructura del Proyecto

```
django-security/
├── django_security/
│   ├── __init__.py
│   ├── conf/
│   │   ├── __init__.py
│   │   └── settings.py          # Configuración segura por defecto
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── security_headers.py
│   │   ├── rate_limiting.py
│   │   ├── request_size_limit.py
│   │   └── suspicious_patterns.py
│   ├── fields/
│   │   ├── __init__.py
│   │   ├── encrypted.py
│   │   └── hashed.py
│   ├── authentication/
│   │   ├── __init__.py
│   │   ├── password_validators.py
│   │   ├── session_security.py
│   │   └── mfa.py
│   ├── validation/
│   │   ├── __init__.py
│   │   ├── input_validators.py
│   │   └── output_encoding.py
│   ├── logging/
│   │   ├── __init__.py
│   │   ├── security_events.py
│   │   └── audit_trail.py
│   ├── storage/
│   │   ├── __init__.py
│   │   └── encrypted_storage.py
│   ├── admin/
│   │   ├── __init__.py
│   │   └── hardening.py
│   ├── management/
│   │   └── commands/
│   │       ├── security_report.py
│   │       └── check_security.py
│   └── checks.py
├── docs/
│   ├── ISO27001_MAPPING.md
│   ├── OWASP_MAPPING.md
│   └── IMPLEMENTATION_GUIDE.md
├── examples/
│   └── secure_starter/
└── tests/
```

---

## A. NÚCLEO IMPRESCINDIBLE

### 1. Configuración Segura de Django por Defecto

**Módulo:** `django_security.conf.settings`

**Funcionalidad:**
- Aplicar configuración segura automáticamente al instalar
- Valores default seguros que se pueden sobrescribir

**Settings a forzar/validar:**

```python
SECURE_DEFAULTS = {
    # SSL/TLS
    'SECURE_SSL_REDIRECT': True,
    'SECURE_PROXY_SSL_HEADER': ('HTTP_X_FORWARDED_PROTO', 'https'),

    # Cookies
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'CSRF_COOKIE_SECURE': True,
    'CSRF_COOKIE_HTTPONLY': True,
    'CSRF_COOKIE_SAMESITE': 'Strict',

    # Headers de seguridad
    'SECURE_HSTS_SECONDS': 31536000,  # 1 año
    'SECURE_HSTS_INCLUDE_SUBDOMAINS': True,
    'SECURE_HSTS_PRELOAD': True,
    'SECURE_CONTENT_TYPE_NOSNIFF': True,
    'SECURE_BROWSER_XSS_FILTER': True,
    'X_FRAME_OPTIONS': 'DENY',

    # Timeouts
    'SESSION_COOKIE_AGE': 3600,  # 1 hora
    'PASSWORD_RESET_TIMEOUT': 3600,
}
```

**Validaciones críticas:**
- `DEBUG = False` en producción
- `ALLOWED_HOSTS` no vacío y sin wildcards peligrosos (`*`)
- `SECRET_KEY` no hardcodeado, mínimo 50 caracteres
- `CSRF_TRUSTED_ORIGINS` configurado correctamente

**Implementación:**

```python
# django_security/conf/settings.py
def apply_secure_defaults(settings_module):
    """Aplica defaults seguros a settings de Django"""
    pass

# django_security/checks.py
from django.core.checks import Error, Warning, register

@register('security')
def check_security_settings(app_configs, **kwargs):
    """System check para validar configuración de seguridad"""
    errors = []
    # Validar DEBUG, ALLOWED_HOSTS, SECRET_KEY, etc.
    return errors
```

**Comando de validación:**
```bash
python manage.py check --deploy --tag security
```

---

### 2. Middlewares de Protección HTTP

#### 2.1 SecurityHeadersMiddleware

**Módulo:** `django_security.middleware.security_headers`

**Headers a añadir:**

```python
SECURITY_HEADERS = {
    # Content Security Policy
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
    'Content-Security-Policy-Report-Only': None,  # Para modo reporte

    # Otros headers
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
}
```

**Configuración:**

```python
DJANGO_SEC = {
    'CSP_POLICY': 'strict' | 'moderate' | 'custom',
    'CSP_REPORT_URI': '/api/csp-report/',
    'CSP_REPORT_ONLY': False,
}
```

**Decorador para override por vista:**

```python
from django_security.decorators import csp_exempt, csp_update

@csp_update(script_src=["'self'", "cdn.example.com"])
def my_view(request):
    pass
```

#### 2.2 RateLimitingMiddleware

**Módulo:** `django_security.middleware.rate_limiting`

**Estrategias:**
- **Fixed Window**: Límite fijo por ventana de tiempo
- **Sliding Window**: Límite deslizante más preciso
- **Token Bucket**: Para burst traffic controlado

**Configuración:**

```python
DJANGO_SEC = {
    'RATE_LIMITING': {
        'ENABLED': True,
        'STRATEGY': 'sliding_window',  # fixed_window, sliding_window, token_bucket
        'DEFAULT_LIMITS': {
            'anonymous': '100/h',
            'authenticated': '1000/h',
        },
        'PER_ENDPOINT': {
            '/api/login/': '5/m',
            '/api/register/': '3/h',
            '/api/expensive-query/': '10/h',
        },
        'BACKEND': 'redis',  # redis, cache, memory
        'BLOCK_ACTION': 'block',  # block, degrade, log
    }
}
```

**Decorador:**

```python
from django_security.decorators import rate_limit

@rate_limit('10/m', key='user')  # por usuario
@rate_limit('100/h', key='ip')   # por IP
def api_endpoint(request):
    pass
```

**Respuesta 429:**

```json
{
    "error": "Rate limit exceeded",
    "retry_after": 45,
    "limit": "10/m"
}
```

#### 2.3 RequestSizeLimitMiddleware

**Módulo:** `django_security.middleware.request_size_limit`

**Configuración:**

```python
DJANGO_SEC = {
    'REQUEST_SIZE_LIMITS': {
        'DEFAULT_MAX_SIZE': 10 * 1024 * 1024,  # 10MB
        'MAX_UPLOAD_SIZE': 100 * 1024 * 1024,   # 100MB
        'PER_ENDPOINT': {
            '/api/upload/': 500 * 1024 * 1024,  # 500MB
            '/api/profile/': 5 * 1024 * 1024,    # 5MB
        },
    }
}
```

**Respuesta 413:**

```json
{
    "error": "Payload too large",
    "max_size": 10485760,
    "received_size": 15728640
}
```

#### 2.4 SuspiciousPatternsMiddleware

**Módulo:** `django_security.middleware.suspicious_patterns`

**Patrones a detectar:**

```python
SUSPICIOUS_PATTERNS = {
    'paths': [
        r'/wp-admin',
        r'/phpmyadmin',
        r'/config\.php',
        r'/\.env',
        r'/\.git',
        r'/admin\.php',
    ],
    'query_strings': [
        r'UNION\s+SELECT',
        r'<script',
        r'javascript:',
        r'\.\./\.\.',
        r'base64_decode',
    ],
    'user_agents': [
        r'sqlmap',
        r'nikto',
        r'nmap',
    ]
}
```

**Acciones:**
- Loggear evento de seguridad
- Marcar IP como sospechosa (aumentar rate limit)
- Opcionalmente bloquear request (403/404)
- Integración con IP reputation system

**Configuración:**

```python
DJANGO_SEC = {
    'SUSPICIOUS_PATTERNS': {
        'ENABLED': True,
        'ACTION': 'log',  # log, block, degrade
        'AUTO_BLOCK_THRESHOLD': 5,  # Bloquear IP tras 5 patrones sospechosos
        'BLOCK_DURATION': 3600,  # 1 hora
    }
}
```

---

### 3. Protección de Autenticación y Sesiones

#### 3.1 Password & Auth Hardening

**Módulo:** `django_security.authentication.password_validators`

**Validadores de contraseña:**

```python
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django_security.authentication.password_validators.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12}
    },
    {
        'NAME': 'django_security.authentication.password_validators.ComplexityValidator',
        'OPTIONS': {
            'min_uppercase': 1,
            'min_lowercase': 1,
            'min_digits': 1,
            'min_special': 1,
        }
    },
    {
        'NAME': 'django_security.authentication.password_validators.CommonPasswordValidator',
    },
    {
        'NAME': 'django_security.authentication.password_validators.BreachedPasswordValidator',
        # Chequea contra Have I Been Pwned API
    },
]
```

**Brute Force Protection:**

```python
DJANGO_SEC = {
    'AUTH_PROTECTION': {
        'MAX_LOGIN_ATTEMPTS': 5,
        'LOCKOUT_DURATION': 900,  # 15 minutos
        'LOCKOUT_STRATEGY': 'exponential',  # fixed, exponential
        'NOTIFICATION': {
            'EMAIL_ON_LOCKOUT': True,
            'EMAIL_ON_SUSPICIOUS_LOGIN': True,  # IP/geo desconocida
        }
    }
}
```

**Middleware de login:**

```python
# django_security/authentication/middleware.py
class LoginProtectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Registrar intentos de login
        # Aplicar delays crecientes
        # Bloquear cuenta tras X intentos
        pass
```

#### 3.2 Session Security

**Módulo:** `django_security.authentication.session_security`

**Configuración:**

```python
DJANGO_SEC = {
    'SESSION_SECURITY': {
        'ABSOLUTE_TIMEOUT': 28800,  # 8 horas max
        'INACTIVITY_TIMEOUT': 3600,  # 1 hora inactividad
        'ROTATE_ON_LOGIN': True,     # Prevenir session fixation
        'BIND_TO_IP': True,          # Validar IP no cambia
        'BIND_TO_USER_AGENT': False, # Opcional, puede causar problemas
    }
}
```

**Middleware:**

```python
class SessionSecurityMiddleware:
    def __call__(self, request):
        # Validar timeouts
        # Validar IP binding
        # Rotar session ID en eventos críticos
        pass
```

#### 3.3 MFA Ready

**Módulo:** `django_security.authentication.mfa`

**Decoradores:**

```python
from django_security.authentication.mfa import require_mfa

@require_mfa(methods=['totp', 'webauthn'])
def sensitive_view(request):
    pass
```

**Middleware:**

```python
class MFAMiddleware:
    """Valida que vistas marcadas requieran MFA completado"""
    pass
```

**Integración con backends:**
- TOTP (pyotp)
- WebAuthn (python-webauthn)
- SMS (integración con Twilio, etc.)

---

### 4. Validaciones y Sanitización

#### 4.1 Input Validation Layer

**Módulo:** `django_security.validation.input_validators`

**Decorador de validación:**

```python
from django_security.validation import validate_input

@validate_input({
    'email': 'email',
    'phone': 'phone',
    'uuid': 'uuid',
    'age': ('int', {'min': 0, 'max': 150}),
    'status': ('choice', {'choices': ['active', 'inactive']}),
})
def create_user(request):
    pass
```

**Integración con DRF:**

```python
from django_security.validation.serializers import SecureSerializer

class UserSerializer(SecureSerializer):
    class Meta:
        model = User
        fields = ['email', 'phone', 'age']
        validators = {
            'email': 'email',
            'phone': 'phone',
        }
```

#### 4.2 Model Field Wrappers

**Módulo:** `django_security.fields.encrypted`

**Campos cifrados:**

```python
from django_security.fields import EncryptedCharField, EncryptedTextField, EncryptedJSONField

class User(models.Model):
    ssn = EncryptedCharField(max_length=11, pii=True)
    medical_data = EncryptedJSONField(sensitive=True)
    notes = EncryptedTextField(blank=True)
```

**Backend de cifrado:**

```python
DJANGO_SEC = {
    'ENCRYPTED_FIELDS_BACKEND': 'fernet',  # fernet, kms
    'ENCRYPTION_KEY': env('ENCRYPTION_KEY'),  # Para Fernet
    'KMS_CONFIG': {
        'provider': 'aws',  # aws, gcp, azure
        'key_id': 'arn:aws:kms:...',
    }
}
```

**Campo hash:**

```python
from django_security.fields import HashedField

class User(models.Model):
    # Solo almacena hash, no se puede recuperar
    rut = HashedField(max_length=12, algorithm='sha256', pii=True)
```

**Flags de campos:**

```python
class User(models.Model):
    email = models.EmailField(pii=True)
    password = models.CharField(max_length=128, sensitive=True)

    class Meta:
        pii_fields = ['email', 'ssn']
        sensitive_fields = ['password', 'medical_data']
```

**Admin integration:**

```python
# Ofuscación automática en admin
class UserAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        # Auto-mask sensitive fields
        pass
```

#### 4.3 Output Encoding Helpers

**Módulo:** `django_security.validation.output_encoding`

**Template filters:**

```django
{{ user_input|safe_html }}
{{ data|safe_json }}
{{ url|safe_url }}
```

**Decorador de vista:**

```python
from django_security.decorators import secure_response

@secure_response(exclude_fields=['password', 'token', 'secret'])
def api_view(request):
    return JsonResponse(data)
```

---

### 5. Protección CSRF / XSS / Clickjacking / Injection

**Módulo:** `django_security.validation`

**Sanitización HTML:**

```python
from django_security.validation import sanitize_html

clean_html = sanitize_html(
    user_html,
    allowed_tags=['p', 'a', 'strong', 'em'],
    allowed_attributes={'a': ['href', 'title']}
)
```

**Campo de rich text seguro:**

```python
from django_security.fields import SafeHTMLField

class Post(models.Model):
    content = SafeHTMLField()  # Auto-sanitiza
```

**Protección mass assignment:**

```python
from django_security.utils import safe_update

# Solo permite campos en whitelist
safe_update(user, request.POST, allowed_fields=['email', 'name'])
```

**Query filtering seguro:**

```python
from django_security.utils import safe_filter

# Solo permite filtrar por campos permitidos
queryset = safe_filter(
    User.objects.all(),
    request.GET,
    allowed_fields=['email', 'is_active'],
    allowed_ordering=['created_at', '-created_at']
)
```

---

### 6. Logging de Seguridad y Auditoría

#### 6.1 Security Event Logger

**Módulo:** `django_security.logging.security_events`

**Eventos estándar:**

```python
from django_security.logging import log_security_event

log_security_event(
    event_type='login_failed',
    user=user,
    ip_address=get_client_ip(request),
    user_agent=request.META.get('HTTP_USER_AGENT'),
    metadata={'reason': 'invalid_password'}
)
```

**Tipos de eventos:**
- `login_succeeded`
- `login_failed`
- `logout`
- `password_changed`
- `permission_denied`
- `suspicious_request`
- `rate_limited`
- `data_exported`
- `data_deleted`
- `settings_changed`

**Configuración:**

```python
DJANGO_SEC = {
    'SECURITY_LOGGING': {
        'ENABLED': True,
        'BACKENDS': ['django', 'syslog', 'json'],
        'SYSLOG_ADDRESS': '/dev/log',
        'JSON_FILE': '/var/log/security.json',
        'SIEM_INTEGRATION': {
            'enabled': False,
            'provider': 'splunk',  # splunk, datadog, elk
            'endpoint': 'https://...',
        }
    }
}
```

#### 6.2 Request Audit Trail

**Módulo:** `django_security.logging.audit_trail`

**Middleware:**

```python
class AuditTrailMiddleware:
    def __call__(self, request):
        # Log: user, IP, endpoint, method, status, duration
        # NO loggear campos sensitive
        pass
```

**Modelo de auditoría:**

```python
class RequestAudit(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, null=True)
    ip_address = models.GenericIPAddressField()
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    status_code = models.IntegerField()
    duration_ms = models.IntegerField()
    user_agent = models.TextField()
```

**Admin Audit:**

```python
class AdminAuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User)
    action = models.CharField(max_length=20)  # create, update, delete
    model = models.CharField(max_length=100)
    object_id = models.CharField(max_length=100)
    changes = models.JSONField()  # Diff de cambios
```

---

### 7. Chequeos de Configuración & Self-Assessment

**Módulo:** `django_security.management.commands.security_report`

**Comando:**

```bash
python manage.py security_report --format=html --output=report.html
```

**Secciones del reporte:**

1. **Configuración Django:**
   - DEBUG status
   - ALLOWED_HOSTS
   - SECRET_KEY strength
   - Cookies security
   - HSTS, CSP, headers

2. **Dependencias:**
   - Vulnerabilidades conocidas (CVE)
   - Paquetes desactualizados
   - Licencias problemáticas

3. **Endpoints:**
   - Endpoints sin autenticación
   - Endpoints sin rate limiting
   - Endpoints "expensive"

4. **Usuarios y permisos:**
   - Superusers
   - Staff users
   - Permisos peligrosos

5. **Compliance:**
   - Checklist OWASP Top 10
   - Controles ISO 27001 implementados

**Formatos de salida:**
- Consola (colorizado)
- HTML (para auditorías)
- JSON (para CI/CD)
- Markdown

---

## B. EXTENSIONES VALIOSAS (SHOULD-HAVE)

### 8. Gestión de Secretos y Llaves

**Módulo:** `django_security.secrets`

**API unificada:**

```python
from django_security.secrets import get_secret

db_password = get_secret('DATABASE_PASSWORD')
api_key = get_secret('STRIPE_API_KEY', version='latest')
```

**Configuración:**

```python
DJANGO_SEC = {
    'SECRETS_BACKEND': 'vault',  # vault, aws_kms, gcp_kms, doppler
    'SECRETS_CONFIG': {
        'vault': {
            'url': 'https://vault.example.com',
            'token': env('VAULT_TOKEN'),
        },
        'aws_kms': {
            'region': 'us-east-1',
            'key_id': 'alias/my-key',
        }
    },
    'ROTATION': {
        'enabled': True,
        'max_age_days': 90,
        'warning_days': 7,
    }
}
```

**Monitoreo:**

```python
# Log de acceso a secretos
class SecretAccessLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    secret_name = models.CharField(max_length=255)
    accessed_by = models.ForeignKey(User)
    purpose = models.CharField(max_length=255)
```

---

### 9. Seguridad en Archivos y Storage

**Módulo:** `django_security.storage`

**Campo de archivo cifrado:**

```python
from django_security.fields import EncryptedFileField

class Document(models.Model):
    file = EncryptedFileField(
        upload_to='documents/',
        max_upload_size=100*1024*1024,
        allowed_extensions=['.pdf', '.docx'],
        scan_for_malware=True,
    )
```

**Validación de archivos:**

```python
from django_security.storage.validators import FileValidator

validator = FileValidator(
    allowed_extensions=['.jpg', '.png'],
    allowed_mimetypes=['image/jpeg', 'image/png'],
    max_size=5*1024*1024,
    validate_content=True,  # MIME sniffing
)
```

**URLs firmadas:**

```python
from django_security.storage import generate_signed_url

url = generate_signed_url(
    file_path='documents/report.pdf',
    expires_in=3600,  # 1 hora
    permissions=['read'],
)
```

**Integración antivirus:**

```python
DJANGO_SEC = {
    'FILE_SCANNING': {
        'enabled': True,
        'provider': 'clamav',  # clamav, virustotal
        'clamav_socket': '/var/run/clamav/clamd.ctl',
        'action_on_virus': 'quarantine',  # quarantine, delete, reject
    }
}
```

---

### 10. Hardening del Admin de Django

**Módulo:** `django_security.admin.hardening`

**Características:**

```python
DJANGO_SEC = {
    'ADMIN_HARDENING': {
        'CUSTOM_URL': '/secret-admin-panel/',  # Ocultar /admin
        'REQUIRE_MFA': True,
        'IP_WHITELIST': ['192.168.1.0/24'],
        'CAPTCHA_ON_FAILED_LOGIN': 3,  # Tras 3 intentos
        'MAX_LOGIN_ATTEMPTS': 5,
        'SESSION_TIMEOUT': 1800,  # 30 min
    }
}
```

**Panel de seguridad en admin:**

```python
class SecurityDashboard(admin.ModelAdmin):
    """Panel con métricas de seguridad"""

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('security/', self.admin_site.admin_view(self.security_dashboard)),
        ]
        return custom_urls + urls

    def security_dashboard(self, request):
        context = {
            'recent_security_events': SecurityEvent.objects.recent(),
            'users_with_dangerous_permissions': User.objects.superusers(),
            'stale_passwords': User.objects.password_not_changed(days=90),
            'failed_logins': FailedLogin.objects.recent(),
        }
        return render(request, 'admin/security_dashboard.html', context)
```

---

### 11. Protección de APIs (REST/GraphQL)

**Módulo:** `django_security.api`

**Integración DRF:**

```python
from django_security.api.throttling import SecureThrottle
from django_security.api.permissions import SecurePermission

class UserViewSet(viewsets.ModelViewSet):
    throttle_classes = [SecureThrottle]
    permission_classes = [SecurePermission]

    # Campos permitidos para filtrado
    filterset_fields = ['email', 'is_active']
    ordering_fields = ['created_at']
    search_fields = ['email', 'first_name']
```

**Decorador para endpoints caros:**

```python
from django_security.decorators import expensive_endpoint

@expensive_endpoint(rate_limit='5/h')
def generate_report(request):
    # Endpoint costoso
    pass
```

**Protección IDs secuenciales:**

```python
from django_security.fields import HashIDField

class Resource(models.Model):
    # Expone hash en lugar de ID secuencial
    public_id = HashIDField(source_field='id', salt='my-salt')
```

---

### 12. Soporte para Políticas de Datos (ISO 27001)

**Módulo:** `django_security.data_policies`

**Configuración en modelos:**

```python
from django_security.data_policies import DataRetentionMixin

class UserActivity(DataRetentionMixin, models.Model):
    user = models.ForeignKey(User)
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        retention_days = 365
        pseudonymize_after_days = 90
        delete_after_days = 730
```

**Management command:**

```bash
python manage.py apply_data_policies --dry-run
python manage.py apply_data_policies --execute
```

**Registro de operaciones:**

```python
class DataOperationLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    operation = models.CharField(max_length=20)  # export, delete, pseudonymize
    model = models.CharField(max_length=100)
    records_affected = models.IntegerField()
    initiated_by = models.ForeignKey(User)
    reason = models.TextField()
```

---

## C. NICE-TO-HAVE / ENTERPRISE

### 13. Integración con SIEM / Observabilidad

**Módulo:** `django_security.integrations.siem`

**Configuración:**

```python
DJANGO_SEC = {
    'SIEM_INTEGRATION': {
        'splunk': {
            'enabled': True,
            'hec_url': 'https://splunk.example.com:8088',
            'hec_token': env('SPLUNK_HEC_TOKEN'),
        },
        'datadog': {
            'enabled': False,
            'api_key': env('DD_API_KEY'),
        },
        'elk': {
            'enabled': False,
            'hosts': ['https://elk.example.com:9200'],
        }
    }
}
```

**Alertas predefinidas:**

```python
SECURITY_ALERTS = [
    {
        'name': 'Brute force attempt',
        'condition': 'login_failed > 10 in 5m from same IP',
        'severity': 'high',
        'notification': ['email', 'slack'],
    },
    {
        'name': 'Privilege escalation',
        'condition': 'permission_granted to superuser',
        'severity': 'critical',
        'notification': ['email', 'pagerduty'],
    },
]
```

---

### 14. Self-Healing / Dynamic Defenses

**Módulo:** `django_security.dynamic_defense`

**IP Reputation System:**

```python
from django_security.reputation import IPReputation

reputation = IPReputation()
reputation.mark_suspicious('192.168.1.100', reason='Multiple failed logins')

if reputation.is_blocked('192.168.1.100'):
    return HttpResponseForbidden()
```

**Feature Toggles:**

```python
from django_security.toggles import SecurityToggle

# Cambiar modo de endpoint dinámicamente
if SecurityToggle.is_enabled('api_strict_mode'):
    # Validaciones extra
    pass
```

**Integración CAPTCHA:**

```python
from django_security.captcha import require_captcha

@require_captcha(threshold=3)  # Tras 3 intentos fallidos
def login(request):
    pass
```

---

### 15. Checklists & Mapeo a OWASP/ISO

**Archivos:** `docs/OWASP_MAPPING.md`, `docs/ISO27001_MAPPING.md`

**Formato del mapeo:**

```markdown
## A01: Broken Access Control

| Control | Implementación | Módulo | Status |
|---------|---------------|--------|--------|
| Deny by default | SecurePermission | django_security.api.permissions | ✅ |
| Rate limiting | RateLimitingMiddleware | django_security.middleware.rate_limiting | ✅ |
| CORS validation | SecurityHeadersMiddleware | django_security.middleware.security_headers | ✅ |
```

**Comando de compliance:**

```bash
python manage.py compliance_report --standard=owasp --level=2
python manage.py compliance_report --standard=iso27001 --annexa
```

---

### 16. Tooling CI/CD

**GitHub Action:**

```yaml
# .github/workflows/security.yml
name: Security Checks
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run security checks
        run: |
          python manage.py check_security --fail-on-warning
          python manage.py test_security
          pip-audit
          safety check
```

**Pre-commit hook:**

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-check
        name: Django Security Check
        entry: python manage.py check_security
        language: system
        pass_filenames: false
```

---

## D. DX, DISEÑO Y ERGONOMÍA

### 17. Configuración Declarativa

```python
# settings.py
DJANGO_SEC = {
    # Perfil de riesgo
    'RISK_PROFILE': 'strict',  # strict, moderate, relaxed, custom

    # Features
    'ENABLE_RATE_LIMITING': True,
    'ENABLE_REQUEST_SIZE_LIMIT': True,
    'ENABLE_SUSPICIOUS_PATTERNS': True,
    'ENABLE_AUDIT_LOGGING': True,
    'ADMIN_HARDENING': True,

    # Backends
    'ENCRYPTED_FIELDS_BACKEND': 'fernet',
    'SECRETS_BACKEND': 'env',
    'CACHE_BACKEND': 'redis',

    # Compliance
    'TARGET_COMPLIANCE': ['owasp-top10', 'iso27001'],
}
```

**Presets por ambiente:**

```python
# settings/dev.py
from django_security.presets import DEV_PRESET
DJANGO_SEC = DEV_PRESET

# settings/prod.py
from django_security.presets import PRODUCTION_PRESET
DJANGO_SEC = PRODUCTION_PRESET
```

---

### 18. Decorators y Mixins

**Decoradores:**

```python
from django_security.decorators import (
    require_mfa,
    secure_endpoint,
    sensitive_view,
    expensive_endpoint,
    rate_limit,
)

@require_mfa
@rate_limit('10/m')
@secure_endpoint(audit=True)
def api_view(request):
    pass

@sensitive_view(mask_fields=['password', 'token'])
def user_detail(request):
    pass
```

**Mixins:**

```python
from django_security.mixins import SecureAPIViewMixin, SecureAdminMixin

class UserViewSet(SecureAPIViewMixin, viewsets.ModelViewSet):
    # Rate limiting, validación, audit automático
    pass

class SecureUserAdmin(SecureAdminMixin, admin.ModelAdmin):
    # MFA, IP whitelist, audit automático
    pass
```

---

### 19. Ejemplos y Plantillas

**Proyecto starter:**

```bash
django-admin startproject --template=https://github.com/yourorg/django-secure-starter myproject
```

**Snippets:**

```python
# Ejemplo DRF con seguridad completa
from django_security.api import SecureModelViewSet

class UserViewSet(SecureModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    # Auto-configurado con:
    # - Rate limiting
    # - Audit logging
    # - Validación de input/output
    # - Encrypted fields
```

---

### 20. Documentación Orientada a Compliance

**Estructura:**

```markdown
# Cómo esta librería te ayuda con ISO 27001

## A.9: Access Control

| Control | Descripción | Implementación |
|---------|-------------|----------------|
| A.9.1.1 | Access control policy | SecurePermission + decorators |
| A.9.2.1 | User registration | Secure user creation with validation |
| A.9.4.1 | Information access restriction | Encrypted fields + access logs |

## Evidencia para auditores

- [Reporte de seguridad](security_report.html)
- [Logs de auditoría](audit_trail.csv)
- [Configuración aplicada](security_config.json)
```

---

## IMPLEMENTACIÓN RECOMENDADA

### Instalación

```bash
pip install django-security
```

### Setup mínimo

```python
# settings.py
INSTALLED_APPS = [
    'django_security',
    ...
]

MIDDLEWARE = [
    'django_security.middleware.SecurityHeadersMiddleware',
    'django_security.middleware.RateLimitingMiddleware',
    'django_security.middleware.RequestSizeLimitMiddleware',
    'django_security.middleware.SuspiciousPatternsMiddleware',
    ...
]

# Importar defaults seguros
from django_security.conf import apply_secure_defaults
apply_secure_defaults(globals())

# Configuración custom
DJANGO_SEC = {
    'RISK_PROFILE': 'strict',
}
```

### Validación

```bash
python manage.py check_security
python manage.py security_report
```

---

## TESTING

Cada módulo debe tener tests completos:

```python
# tests/test_rate_limiting.py
from django.test import TestCase
from django_security.middleware import RateLimitingMiddleware

class RateLimitingTests(TestCase):
    def test_rate_limit_enforced(self):
        # Test que rate limit se aplica correctamente
        pass

    def test_rate_limit_per_user(self):
        # Test límite por usuario
        pass
```

---

## DEPENDENCIAS PRINCIPALES

```txt
Django>=4.2
djangorestframework>=3.14
cryptography>=41.0  # Para encrypted fields
redis>=4.0  # Para rate limiting
bleach>=6.0  # Para sanitización HTML
pyotp>=2.9  # Para TOTP MFA
```

---

## ROADMAP DE IMPLEMENTACIÓN

1. **Fase 1 (MVP):** Secciones A.1-A.7 (núcleo imprescindible)
2. **Fase 2:** Secciones B.8-B.12 (extensiones valiosas)
3. **Fase 3:** Secciones C.13-C.16 (enterprise features)
4. **Fase 4:** Documentación, ejemplos, compliance mapping

---

## COMPLIANCE MAPPING

### OWASP Top 10 2021

| Riesgo | Mitigación | Módulo |
|--------|-----------|---------|
| A01: Broken Access Control | Rate limiting, permission checks | middleware.rate_limiting, api.permissions |
| A02: Cryptographic Failures | Encrypted fields, secrets management | fields.encrypted, secrets |
| A03: Injection | Input validation, query filtering | validation.input_validators |
| A04: Insecure Design | Secure defaults, security checks | conf.settings, checks |
| A05: Security Misconfiguration | Security report, config validation | management.commands.security_report |
| A06: Vulnerable Components | Dependency scanning (CI/CD) | N/A (external) |
| A07: Auth Failures | MFA, brute force protection, session security | authentication.* |
| A08: Data Integrity Failures | Audit logging, signed URLs | logging.audit_trail, storage |
| A09: Logging Failures | Security event logging, SIEM integration | logging.security_events |
| A10: SSRF | Request validation, allowlist | validation.input_validators |

### ISO 27001 Annex A (principales)

| Control | Implementación |
|---------|----------------|
| A.5.1 Políticas de seguridad | Configuración segura por defecto |
| A.8.2 Clasificación de información | Flags pii/sensitive en campos |
| A.9.2 Gestión de acceso de usuarios | MFA, brute force protection |
| A.9.4 Control de acceso a sistemas | Rate limiting, IP whitelist |
| A.10.1 Controles criptográficos | Encrypted fields, KMS integration |
| A.12.4 Logging y monitoreo | Security events, audit trail |
| A.14.2 Seguridad en desarrollo | Secure defaults, validation |
| A.16.1 Gestión de incidentes | Security dashboard, alerting |
| A.18.1 Cumplimiento legal | Data retention policies, audit logs |

---

## NOTAS PARA IMPLEMENTACIÓN CON CLAUDE CODE

1. **Comenzar por el núcleo:** Implementar secciones A.1-A.7 primero
2. **Testing exhaustivo:** Cada feature debe tener tests completos
3. **Documentación inline:** Docstrings detallados en cada clase/función
4. **Ejemplos prácticos:** Incluir ejemplos de uso en docs
5. **Configuración flexible:** Todo debe ser configurable vía DJANGO_SEC
6. **Backward compatibility:** No romper proyectos Django existentes
7. **Performance:** Minimizar overhead de middlewares
8. **Internacionalización:** Mensajes de error en i18n
9. **Type hints:** Usar typing para mejor DX
10. **Pre-commit hooks:** Validación de código con black, isort, flake8

---

## ESTRUCTURA DE ARCHIVOS PRINCIPAL

```
django_security/
├── __init__.py
├── conf/
│   ├── __init__.py
│   ├── settings.py
│   └── presets.py
├── middleware/
│   ├── __init__.py
│   ├── base.py
│   ├── security_headers.py
│   ├── rate_limiting.py
│   ├── request_size_limit.py
│   └── suspicious_patterns.py
├── fields/
│   ├── __init__.py
│   ├── encrypted.py
│   └── hashed.py
├── authentication/
│   ├── __init__.py
│   ├── password_validators.py
│   ├── session_security.py
│   ├── mfa.py
│   └── middleware.py
├── validation/
│   ├── __init__.py
│   ├── input_validators.py
│   ├── output_encoding.py
│   └── serializers.py
├── logging/
│   ├── __init__.py
│   ├── security_events.py
│   ├── audit_trail.py
│   └── models.py
├── storage/
│   ├── __init__.py
│   ├── encrypted_storage.py
│   └── validators.py
├── admin/
│   ├── __init__.py
│   ├── hardening.py
│   └── dashboard.py
├── api/
│   ├── __init__.py
│   ├── throttling.py
│   ├── permissions.py
│   └── viewsets.py
├── data_policies/
│   ├── __init__.py
│   ├── models.py
│   └── tasks.py
├── secrets/
│   ├── __init__.py
│   └── backends/
│       ├── fernet.py
│       ├── kms.py
│       └── vault.py
├── integrations/
│   └── siem/
│       ├── splunk.py
│       ├── datadog.py
│       └── elk.py
├── management/
│   └── commands/
│       ├── security_report.py
│       ├── check_security.py
│       └── apply_data_policies.py
├── decorators.py
├── mixins.py
├── utils.py
└── checks.py
```

---

Esta especificación proporciona el contexto completo para implementar la librería con Claude Code. Cada sección puede ser implementada de forma modular e incremental.
