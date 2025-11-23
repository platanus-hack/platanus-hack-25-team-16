# Django Security Suite

<div align="center">
  <img src="./dss-logo.png" alt="Django Security Suite Logo" width="300" />
</div>

## El problema

Implementar seguridad robusta en aplicaciones web requiere semanas de desarrollo y conocimiento especializado. La mayoría de equipos lanzan productos con seguridad insuficiente, exponiendo datos sensibles.

## La solución

**Django Security Suite** - El único paquete Django que agrega protección enterprise en minutos.

## ¿Por qué debemos ganar?

### 1. Resolvemos un problema REAL que cuesta millones
Cada data breach cuesta en promedio **$4.45M USD** (IBM 2023). Las fintechs no tienen semanas para implementar seguridad - necesitan lanzar rápido sin comprometer datos sensibles. **Somos la única solución Django que permite esto**.

### 2. Innovación técnica única: Búsqueda sobre datos encriptados
**Nadie más en Django hace esto**. Otras soluciones te obligan a desencriptar o usar servicios externos costosos:

```python
# Los datos se encriptan automáticamente en la base de datos
user.first_name = "Juan"

# Pero puedes buscar sin desencriptar - IMPOSIBLE en otras soluciones
users = User.objects.filter(first_name__contains='Jua')  # Funciona!
```

**Tecnología**: N-gram indexing + hash SHA-256. Esto es nivel enterprise que normalmente requiere infraestructura dedicada.

### 3. Ya está en producción y disponible públicamente
No es un prototipo - **está publicado en PyPI** y funcionando:
- **50+ usuarios demo** con datos encriptados
- **30+ test endpoints** validando cada protección OWASP
- **<200ms** de respuesta con encriptación activa
- **100% compliance** ISO 27001

### 4. Impacto medible inmediato
| Métrica | Sin DSS | Con DSS |
|---------|---------|---------|
| **Setup OWASP Top 10** | 2-3 semanas | 5 minutos |
| **Costo implementación** | $15K-30K USD | $0 (open source) |
| **Búsqueda encriptada** | Requiere desencriptar | Nativa |
| **Audit logs** | Modificables | Imposible alterar |
| **Compliance ISO 27001** | Mapeo manual | Built-in |

### 5. Lo que incluimos out-of-the-box

**Protección OWASP Top 10 Completa:**
- SQL Injection, XSS, Path Traversal bloqueados en tiempo real
- Rate limiting (5 req/min por IP)
- Security headers automáticos (CSP, HSTS, X-Frame-Options)

**Auditoría inmutable:**
- Logs encadenados con hash SHA-256 (imposible alterar)
- Enmascaramiento automático de datos sensibles
- Mapeo directo a controles ISO 27001

**Autenticación enterprise:**
- Multi-factor (TOTP/Google Authenticator)
- Protección brute force con lockout automático
- Validación de contraseñas contra 3B+ passwords filtrados

## Demo en vivo

**URL**: https://django-security-suite.deskobar.cl

### Prueba la protección:

**SQL Injection bloqueado:**
```bash
curl "https://django-security-suite.deskobar.cl/api/security-test/test-sql/?query='; DROP TABLE users; --'"
# → 403 Forbidden
```

**Rate Limiting:**
```bash
for i in {1..10}; do curl https://django-security-suite.deskobar.cl/api/security-test/test-rate-limit/; done
# → Primeros 5 OK, resto 429 Too Many Requests
```

**Credenciales:** `ignacio` / `1234`

## ¿Por qué es único?

| Django Security Suite | Soluciones tradicionales |
|----------------------|--------------------------|
| Setup en 5 minutos | 2-3 semanas de desarrollo |
| Búsqueda sobre datos encriptados | Requiere desencriptar o soluciones costosas |
| Logs imposibles de alterar | Logs fácilmente modificables |
| Compliance ISO 27001 built-in | Mapeo manual requerido |

## Stack técnico
- Django 5.2.8 + Python 3.12
- PostgreSQL con encriptación AES-128
- Docker + Gunicorn
- Publicado en PyPI: https://pypi.org/project/django-security-suite/

## El equipo - Team 16

- **Nicolás Ramos** ([@Nicolasramos411](https://github.com/Nicolasramos411))
- **David Escobar** ([@deskobar](https://github.com/deskobar))
- **Ignacio Engelberger** ([@IgnacioEngelberger](https://github.com/IgnacioEngelberger))

## Links

- **PyPI**: https://pypi.org/project/django-security-suite/
- **Demo**: https://django-security-suite.deskobar.cl/admin

---

**Track**: Fintech + Digital Security | **Hackathon**: Platanus Hackathon 2025
