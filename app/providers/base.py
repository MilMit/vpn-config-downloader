"""Plugin base class for VPN provider adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from ..core import CAPABILITY_STATUS_MAP, PROTOCOLS, Capability, Credentials, Event, Location, Options


class Provider(ABC):
    key: str = ''
    label: str = ''
    official_url: str = ''
    description: str = ''
    supports_server_discovery: bool = False
    capabilities: tuple[Capability, ...] = ()
    unsupported_explanations: dict[str, str] = {}

    def discover(self, *, source: str = 'live') -> list[Location]:
        return []

    @abstractmethod
    def export(
        self,
        *,
        locations: list[Location],
        credentials: Credentials,
        options: Options,
        source_path: str,
        emit,
        stop,
        pause,
    ) -> dict:
        pass

    def protocol_matrix(self) -> list[dict]:
        """Return standardized capability status for all 6 protocols.

        Statuses: Supported | Requires Manual Action | Experimental | Unsupported.
        """
        by_proto = {c.protocol: c for c in self.capabilities}
        rows = []
        for proto in PROTOCOLS:
            cap = by_proto.get(proto)
            if cap is not None:
                rows.append({
                    'protocol': proto,
                    'level': cap.level,
                    'status': cap.status,
                    'explanation': cap.explanation,
                })
            else:
                reason = self.unsupported_explanations.get(
                    proto,
                    f'{self.label or self.key} does not provide official standalone export for {proto.upper()}.',
                )
                rows.append({
                    'protocol': proto,
                    'level': 'unsupported',
                    'status': CAPABILITY_STATUS_MAP['unsupported'],
                    'explanation': reason,
                })
        return rows

    def capabilities_string(self) -> str:
        return ' • '.join(f'{c.protocol}: {c.status}' for c in self.capabilities)
