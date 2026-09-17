from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class Observation:
    target: str
    type: str          # напр. "DNS_RECORD", "HTTP_SERVICE"
    value: str          # напр. "93.184.216.34" або "https://example.com"
    source: str          # який модуль/інструмент це виявив
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)