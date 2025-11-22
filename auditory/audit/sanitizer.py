import json
from typing import Any, Tuple

from .policies import BaseMaskingPolicy


def sanitize_body(
    raw_body: bytes, policy: BaseMaskingPolicy | None, max_length: int | None = None
) -> Tuple[bytes, Any]:
    """
    Devuelve cuerpo saneado (bytes) y representación parseada (dict/list/str).
    """
    if not raw_body:
        return b"", None

    body = raw_body
    if max_length and len(body) > max_length:
        body = body[:max_length]

    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        return body, None

    if policy:
        masked = policy.mask_payload(parsed)
    else:
        masked = parsed

    try:
        sanitized_bytes = json.dumps(
            masked, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except Exception:
        sanitized_bytes = body

    return sanitized_bytes, masked
