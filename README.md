# 🔐 Django Security Suite

<div align="center">
  <img src="./dss-logo.png" alt="Django Security Suite Logo" width="300" />
</div>

> **Enterprise-Grade Django Security Suite** - ISO 27001 Compliant
> Platanus Hackathon 2025 - Team 16

[![Track](https://img.shields.io/badge/Track-Fintech%20%2B%20Digital%20Security-764ba2)](https://platanus.cc)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.2%2B-green)](https://djangoproject.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Ready-blue)](https://postgresql.org)

A production-ready Django backend implementing comprehensive security controls for financial applications. Built to demonstrate OWASP Top 10 protection, field-level encryption, and ISO 27001 compliance.

## 🚀 Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd hackathon-backend

# Install dependencies (using uv)
uv sync

# Setup database
uv run python manage.py migrate

# Create demo users (50 users with encrypted PII)
uv run python manage.py seed_users

# Run development server
uv run python manage.py runserver
```

Visit:
- **Landing Page**: http://localhost:8000/
- **OWASP Security Tests**: http://localhost:8000/security-tests/
- **Admin Panel**: http://localhost:8000/admin/

## 🛡️ Security Features

### OWASP Top 10 Protection

| Vulnerability | Protection | Test Endpoint |
|--------------|------------|---------------|
| **A03: Injection** | SQL/XSS/Command injection detection & blocking | `/api/security-test/test-sql/` |
| **A03: Injection** | Input validation & sanitization | `/api/security-test/test-validation/` |
| **A03: XSS** | Automatic HTML/JS escaping in responses | `/api/security-test/test-secure-response/` |
| **A05: Security Misconfiguration** | Comprehensive security headers (CSP, HSTS, etc.) | `/api/security-test/test-headers/` |
| **A07: Auth Failures** | Rate limiting (5 req/min), brute force protection | `/api/security-test/test-rate-limit/` |
| **A09: Logging Failures** | Tamper-evident audit logs with hash chaining | `/api/security-test/test-audit/` |

### Data Protection (ISO 27001 A.10.1)

- **Searchable Encryption**: AES-128 CBC encryption with n-gram indexes for PII
- **Field-Level Encryption**: Using `django-crypto-fields` for sensitive data
- **Key Management**: Secure key storage and rotation support
- **Privacy-Preserving Search**: Query encrypted fields without decryption

```python
# Example: Searchable encrypted fields
class User(AbstractUser):
    first_name = SearchableEncryptedTextField(max_length=150)
    ssn = EncryptedCharField(max_length=11)  # No search needed

# Query works on encrypted data!
users = User.objects.filter(first_name__contains='John')
```

### Authentication & Session Security

- **Multi-Factor Authentication**: TOTP-based 2FA via `django-otp`
- **Brute Force Protection**: Account lockout with exponential backoff via `django-axes`
- **Session Security**: IP binding, inactivity timeout, session rotation
- **Password Policy**: 12+ chars, complexity requirements, HIBP breach checking

### Audit & Compliance

- **Tamper-Evident Logs**: Hash-chained audit trail (ISO 27001 A.12.4.1)
- **API Request Logging**: Complete request/response capture
- **PII Masking**: Automatic detection and redaction in logs
- **Compliance Reports**: ISO 27001 and OWASP mapping

## 🧪 Testing Security Features

### SQL Injection Protection
```bash
# These will be blocked (403 Forbidden)
curl "http://localhost:8000/api/security-test/test-sql/?query='; DROP TABLE users; --'"
curl "http://localhost:8000/api/security-test/test-sql/?query=1' OR '1'='1"
```

### XSS Protection
```bash
# Sensitive fields removed, HTML escaped
curl http://localhost:8000/api/security-test/test-secure-response/
```

### Rate Limiting
```bash
# First 5 succeed, rest get 429 Too Many Requests
for i in {1..10}; do curl http://localhost:8000/api/security-test/test-rate-limit/; done
```

### Input Validation
```bash
# Valid input
curl -X POST http://localhost:8000/api/security-test/test-validation/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "age": 25}'

# Invalid email (400 Bad Request)
curl -X POST http://localhost:8000/api/security-test/test-validation/ \
  -H "Content-Type: application/json" \
  -d '{"email": "invalid", "age": 25}'
```

**📋 Full test documentation**: http://localhost:8000/security-tests/

## 🗄️ Database

PostgreSQL (Neon) with encrypted field support:

```python
# Environment variable
DATABASE_URL=postgresql://user:pass@host/db?sslmode=require

# Automatic connection in settings.py
# Supports both PostgreSQL and SQLite for development
```

## 📦 Tech Stack

- **Framework**: Django 5.2.8
- **Database**: PostgreSQL (with SQLite fallback)
- **Encryption**: `django-crypto-fields` (AES-128 CBC)
- **Authentication**: `django-otp` (TOTP), `django-axes` (brute force)
- **Server**: Gunicorn + WhiteNoise (static files)
- **Python**: 3.12+ with `uv` package manager

## 🔑 Key Components

```
hackathon-backend/
├── app/                          # Main Django project
│   ├── security/                 # Security middleware & decorators
│   │   ├── conf/                 # Security configuration presets
│   │   └── storage/              # Encrypted file storage
│   ├── templates/                # Landing pages
│   │   ├── index.html            # Home page
│   │   └── security_tests.html   # OWASP test documentation
│   └── test_security.py          # Security test endpoints
├── auth_security/                # Authentication & session security
├── data_protection/              # Searchable encryption fields
├── input_validation/             # Input sanitization & validation
├── auditory/                     # Tamper-evident audit logging
├── users/                        # Custom User model with encryption
└── Dockerfile                    # Production-ready container
```

## 🚢 Production Deployment

### Docker (Coolify/Railway)

```bash
# Build
docker build -t django-security-suite .

# Run
docker run -p 8000:8000 \
  -e DATABASE_URL="postgresql://..." \
  -e SECRET_KEY="..." \
  -e ALLOWED_HOSTS="yourdomain.com" \
  django-security-suite
```

### Environment Variables

```bash
SECRET_KEY=<50+ character secret>
DEBUG=False
ALLOWED_HOSTS=yourdomain.com
DATABASE_URL=postgresql://user:pass@host/db
CSRF_TRUSTED_ORIGINS=https://yourdomain.com

# Encryption
DJANGO_CRYPTO_FIELDS_KEY_PATH=/var/lib/crypto_keys
APP_NAME=hackathon-backend
REVISION=0.1.0

# Security Settings
SECURITY_RISK_PROFILE=moderate
ENABLE_RATE_LIMITING=True
```

## 👥 Team 16

- **Nicolás Ramos** ([@Nicolasramos411](https://github.com/Nicolasramos411))
- **David Escobar** ([@deskobar](https://github.com/deskobar))
- **Ignacio Engelberger** ([@IgnacioEngelberger](https://github.com/IgnacioEngelberger))

## 📝 Demo Credentials

After running `seed_users`:

**Superusers (Xpendit Team)**:
- Username: `ignacio`, `nicolas`, or `david`
- Password: `1234`

**Regular Users (47 users)**:
- Email: `free@xpendit.com`, `premium@xpendit.com`, `enterprise@xpendit.com`
- Password: `Test1234!`

## 🏆 Hackathon Track

**Track**: 🛡️ Fintech + Digital Security
**Event**: Platanus Hackathon 2025
**Submission**: November 23, 2025, 9:00 AM Chile Time

---

Built with ❤️ for secure fintech applications

**🔗 Links:** [View Demo](https://django-security-suite.deskobar.cl/admin) | [Test Security](https://django-security-suite.deskobar.cl/api/security-tests/) | [PyPI Package](https://pypi.org/project/django-security-suite/)
