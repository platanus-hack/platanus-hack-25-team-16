from django.conf import settings
from django.core.checks import Error, Warning, register


AUDIT_MIDDLEWARE = "auditory.audit.middleware.AuditContextMiddleware"
USER_CONTEXT_MIDDLEWARE = "auditory.audit.user_context.UserContextEnricher"
HTTP_MIDDLEWARE = "auditory.http.HTTPProtectionMiddleware"


@register()
def middleware_order_check(app_configs, **kwargs):
    errors = []
    middleware = list(getattr(settings, "MIDDLEWARE", []))

    if AUDIT_MIDDLEWARE in middleware and USER_CONTEXT_MIDDLEWARE in middleware:
        if middleware.index(AUDIT_MIDDLEWARE) > middleware.index(USER_CONTEXT_MIDDLEWARE):
            errors.append(
                Error(
                    "AuditContextMiddleware debe ir antes de UserContextEnricher.",
                    id="security.E001",
                )
            )

    if AUDIT_MIDDLEWARE in middleware:
        try:
            auth_index = middleware.index("django.contrib.auth.middleware.AuthenticationMiddleware")
            audit_index = middleware.index(AUDIT_MIDDLEWARE)
            if audit_index > auth_index:
                errors.append(
                    Error(
                        "AuditContextMiddleware debe ejecutarse antes de AuthenticationMiddleware.",
                        id="security.E002",
                    )
                )
        except ValueError:
            errors.append(
                Warning(
                    "AuthenticationMiddleware no está configurado; UserContextEnricher no podrá añadir actor.",
                    id="security.W001",
                )
            )

    if HTTP_MIDDLEWARE in middleware:
        try:
            security_idx = middleware.index("django.middleware.security.SecurityMiddleware")
            http_idx = middleware.index(HTTP_MIDDLEWARE)
            if http_idx < security_idx:
                errors.append(
                    Warning(
                        "HTTPProtectionMiddleware debería ir después de SecurityMiddleware.",
                        id="security.W002",
                    )
                )
        except ValueError:
            errors.append(
                Warning(
                    "SecurityMiddleware no está presente; activa cabeceras base.",
                    id="security.W003",
                )
            )

    return errors


@register()
def config_check(app_configs, **kwargs):
    cfg = getattr(settings, "SECURITY_CONFIG", None)
    if not cfg:
        return [
            Warning(
                "SECURITY_CONFIG no está definido; se usarán valores predeterminados.",
                id="security.W010",
            )
        ]
    return []
