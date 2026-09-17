from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Status(str, Enum):
    OBSERVED = "OBSERVED"       # автоматично зафіксовано, ще не проаналізовано людиною
    HYPOTHESIS = "HYPOTHESIS"   # є підозра, потрібна перевірка (Етап 10)
    VALIDATED = "VALIDATED"     # перевірено вручну, ознаки підтвердились
    CONFIRMED = "CONFIRMED"     # доведено експлуатацією/чітким доказом


@dataclass
class Finding:
    title: str
    target: str
    severity: Severity
    confidence: Confidence
    status: Status
    source_observations: list[dict] = field(default_factory=list)
    description: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value
        return d