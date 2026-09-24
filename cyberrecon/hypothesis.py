from dataclasses import dataclass
from cyberrecon.finding import Confidence


@dataclass
class Hypothesis:
    title: str
    target: str
    vulnerability_type: str
    reasoning: str
    supporting_findings: list[dict]
    confidence: Confidence

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "target": self.target,
            "vulnerability_type": self.vulnerability_type,
            "reasoning": self.reasoning,
            "supporting_findings": self.supporting_findings,
            "confidence": self.confidence.value,
        }