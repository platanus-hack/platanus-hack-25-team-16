import re
from typing import Any, Dict, Protocol

from django.utils.module_loading import import_string


class BaseMaskingPolicy(Protocol):
    def mask_payload(self, payload: Any) -> Any: ...


class StrictMasking:
    """
    Política simple basada en listas de claves sensibles.
    """

    SENSITIVE_KEYS = {
        "password",
        "token",
        "secret",
        "authorization",
        "api_key",
        "card",
        "ssn",
    }
    MASK = "***"

    def mask_payload(self, payload: Any) -> Any:
        if isinstance(payload, dict):
            return {k: self._mask_value(k, v) for k, v in payload.items()}
        if isinstance(payload, list):
            return [self.mask_payload(item) for item in payload]
        return payload

    def _mask_value(self, key: str, value: Any) -> Any:
        normalized_key = key.lower()
        if normalized_key in self.SENSITIVE_KEYS or any(
            tag in normalized_key for tag in ("pass", "secret", "token")
        ):
            return self.MASK
        if isinstance(value, dict):
            return self.mask_payload(value)
        if isinstance(value, list):
            return [self.mask_payload(v) for v in value]
        if isinstance(value, str) and re.search(r"\d{6,}", value):
            return self.MASK
        return value


def load_policy(cfg: Dict[str, Any]) -> BaseMaskingPolicy | None:
    policy_path = cfg.get("AUDIT_LOG", {}).get("PII_MASKING")
    if not policy_path:
        return None
    try:
        policy_cls = import_string(policy_path)
        return policy_cls()
    except Exception:
        return StrictMasking()
