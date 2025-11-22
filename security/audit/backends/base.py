from __future__ import annotations

from typing import Any, Dict, Protocol


class BaseAuditBackend(Protocol):
    def append(self, event: Dict[str, Any]) -> None: ...

    def verify_chain(self) -> Dict[str, Any]: ...

    def prune(self, retention_days: int) -> int: ...


def canonical_json(payload: Any) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
