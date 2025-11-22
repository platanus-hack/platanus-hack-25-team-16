import logging
import math
from copy import deepcopy
from typing import Any, Dict

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Import checks to register system checks at app load
from . import checks  # noqa: F401

logger = logging.getLogger(__name__)


DEFAULT_SECURITY_CONFIG: Dict[str, Any] = {
    "COMPLIANCE_STANDARD": "ISO27001",
    "AUDIT_LOG": {
        "ENABLED": True,
        "DECOUPLED_MODE": True,
        "HASH_CHAINING": True,
        "HASH_KEY_ENV": "AUDIT_HASH_KEY",
        "STORAGE_BACKEND": "security.audit.backends.tamper_evident.TamperEvidentPostgres",
        "PII_MASKING": "security.audit.policies.StrictMasking",
        "MODELS": [],
        "RETENTION_DAYS": 180,
        "MAX_BODY_LENGTH": 8192,
    },
    "HTTP_SECURITY": {
        "ENABLED": True,
        "HSTS_SECONDS": 31536000,
        "CSP_ENFORCE": True,
        "X_FRAME_OPTIONS": "DENY",
    },
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probs = [float(value.count(c)) / len(value) for c in set(value)]
    return -sum(p * math.log2(p) for p in probs)


def _merge_config(user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(DEFAULT_SECURITY_CONFIG)
    for key, val in (user_cfg or {}).items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key].update(val)
        else:
            merged[key] = val
    return merged


def _validate_runtime(cfg: Dict[str, Any]) -> None:
    debug = getattr(settings, "DEBUG", False)
    allowed_hosts = getattr(settings, "ALLOWED_HOSTS", [])
    secret_key = getattr(settings, "SECRET_KEY", "")

    if not debug:
        if allowed_hosts in ([], ["*"], ["*.*"], "*"):
            raise ImproperlyConfigured("ALLOWED_HOSTS no puede estar vacío ni ser comodín en producción.")

        if _entropy(secret_key) < 3.5:
            raise ImproperlyConfigured("SECRET_KEY no tiene entropía suficiente para producción.")
    else:
        if allowed_hosts in ([], ["*"], ["*.*"], "*"):
            logger.warning("ALLOWED_HOSTS está permisivo; ajusta antes de producción.")
        if _entropy(secret_key) < 3.5:
            logger.warning("SECRET_KEY tiene entropía baja; genera una clave fuerte para producción.")


class SecurityConfig(AppConfig):
    name = "security"
    verbose_name = "Security Library"

    def ready(self) -> None:
        cfg = _merge_config(getattr(settings, "SECURITY_CONFIG", {}))
        _validate_runtime(cfg)

        from .registry import security_state
        from .audit.backends import load_backend
        from .audit.policies import load_policy
        from .audit.signals import register_signals

        backend = load_backend(cfg)
        policy = load_policy(cfg)
        security_state.set(config=cfg, backend=backend, policy=policy)

        register_signals(cfg, backend, policy)

        logger.info("Security library inicializada con backend %s", backend.__class__.__name__)
