from dataclasses import dataclass, field


@dataclass
class ValidationPlan:
    hypothesis_title: str
    target: str
    steps: list[str] = field(default_factory=list)
    tools_needed: list[str] = field(default_factory=list)
    caution: str = ""

    def to_dict(self) -> dict:
        return {
            "hypothesis_title": self.hypothesis_title,
            "target": self.target,
            "steps": self.steps,
            "tools_needed": self.tools_needed,
            "caution": self.caution,
        }