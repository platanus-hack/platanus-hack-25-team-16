from dataclasses import dataclass
from typing import Any, Dict, Optional

from auditory.audit.backends.base import BaseAuditBackend
from auditory.audit.policies import BaseMaskingPolicy


@dataclass
class _SecurityState:
    config: Dict[str, Any]
    backend: BaseAuditBackend
    policy: Optional[BaseMaskingPolicy]


class _SecurityStateHolder:
    def __init__(self) -> None:
        self._state: Optional[_SecurityState] = None

    def set(self, config: Dict[str, Any], backend: BaseAuditBackend, policy: Optional[BaseMaskingPolicy]) -> None:
        self._state = _SecurityState(config=config, backend=backend, policy=policy)

    def get_config(self) -> Dict[str, Any]:
        if not self._state:
            return {}
        return self._state.config

    def get_backend(self) -> Optional[BaseAuditBackend]:
        if not self._state:
            return None
        return self._state.backend

    def get_policy(self) -> Optional[BaseMaskingPolicy]:
        if not self._state:
            return None
        return self._state.policy


security_state = _SecurityStateHolder()
