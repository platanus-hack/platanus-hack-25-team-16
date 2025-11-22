# Input Validation & Sanitization App

Django app que proporciona validación y sanitización completa de entrada de datos para prevenir vulnerabilidades web comunes.

## Características

### Validadores

Validadores personalizados para Django y Django REST Framework:

- `StrictEmailValidator` - Validación estricta de emails con prevención de inyección de headers
- `UsernameValidator` - Validación de usernames con reglas estrictas
- `NoSQLInjectionValidator` - Detección de patrones de inyección SQL
- `NoXSSValidator` - Detección de patrones XSS
- `NoCommandInjectionValidator` - Prevención de inyección de comandos
- `SafeURLValidator` - Validación de URLs con prevención SSRF
- `PhoneNumberValidator` - Validación de números telefónicos internacionales
- `NoPathTraversalValidator` - Prevención de path traversal
- `ContentLengthValidator` - Límites de longitud de contenido
- `AlphanumericValidator` - Validación alfanumérica

### Sanitizadores

Utilidades para limpiar datos de entrada:

- `InputSanitizer` - Sanitización de diferentes tipos de entrada
- `DictSanitizer` - Sanitización de diccionarios (útil para JSON)
- `sanitize_request_data()` - Función de conveniencia

### Serializers Seguros

Serializers de DRF con validación y sanitización integrada:

- `SecureCharField` - Campo de texto seguro
- `SecureEmailField` - Campo de email con validación estricta
- `SecureURLField` - Campo de URL con prevención SSRF
- `UsernameField` - Campo de username
- `PhoneNumberField` - Campo de teléfono
- `SecureFilePathField` - Campo de ruta de archivo
- `AlphanumericField` - Campo alfanumérico
- `SecureSerializerMixin` - Mixin para sanitización automática

### Middleware

- `RequestSanitizationMiddleware` - Sanitización automática de requests
- `ContentSecurityPolicyMiddleware` - Headers CSP
- `SecurityHeadersMiddleware` - Headers de seguridad estándar
- `RequestSizeLimitMiddleware` - Límites de tamaño de request

## Instalación

1. Añadir a `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    'input_validation',
]
```

2. Añadir middleware (opcional):

```python
MIDDLEWARE = [
    # ...
    'input_validation.middleware.RequestSanitizationMiddleware',
    'input_validation.middleware.ContentSecurityPolicyMiddleware',
    'input_validation.middleware.SecurityHeadersMiddleware',
    'input_validation.middleware.RequestSizeLimitMiddleware',
]
```

## Uso

### Validators en Modelos

```python
from django.db import models
from input_validation.validators import StrictEmailValidator, PhoneNumberValidator

class User(models.Model):
    email = models.EmailField(validators=[StrictEmailValidator()])
    phone = models.CharField(validators=[PhoneNumberValidator()])
```

### Serializers Seguros

```python
from rest_framework import serializers
from input_validation.serializers import SecureCharField, SecureEmailField

class UserSerializer(serializers.Serializer):
    name = SecureCharField(max_length=100)
    email = SecureEmailField()
```

### Sanitización Manual

```python
from input_validation.sanitizers import InputSanitizer

sanitizer = InputSanitizer()
clean_email = sanitizer.sanitize_email(user_input)
clean_html = sanitizer.sanitize_html(user_content)
```

## Tests

Ejecutar tests:

```bash
python manage.py test input_validation
```

## Documentación

Ver:
- [VALIDATION_SANITIZATION_GUIDE.md](../VALIDATION_SANITIZATION_GUIDE.md) - Guía completa
- [VALIDATION_IMPLEMENTATION_SUMMARY.md](../VALIDATION_IMPLEMENTATION_SUMMARY.md) - Resumen técnico

## Vulnerabilidades Prevenidas

- XSS (Cross-Site Scripting)
- SQL Injection
- Command Injection
- Path Traversal
- SSRF (Server-Side Request Forgery)
- Email Header Injection
- DoS (Denial of Service)
- HTML Injection
