from __future__ import annotations

from typing import Any, Dict, Protocol


class BaseAuditBackend(Protocol):
    def append(self, event: Dict[str, Any]) -> None: ...

    def verify_chain(self) -> Dict[str, Any]: ...

    def prune(self, retention_days: int) -> int: ...


def canonical_json(payload: Any) -> str:
    import json
    from decimal import Decimal
    from datetime import datetime, date

    class CanonicalEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Decimal):
                return float(obj)
            if isinstance(obj, (datetime, date)):
                return obj.isoformat()
            return super().default(obj)

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, cls=CanonicalEncoder)
