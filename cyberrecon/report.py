from datetime import datetime, timezone
from pathlib import Path
from cyberrecon.finding import Finding, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def generate_report(target: str, findings: list[Finding], output_path: Path) -> None:
    lines = [
        f"# CyberRecon Report: {target}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Total findings: {len(findings)}",
        "",
    ]

    for severity in _SEVERITY_ORDER:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue

        lines.append(f"## {severity.value} ({len(group)})")
        lines.append("")

        for f in group:
            lines.append(f"### {f.title}")
            lines.append(f"- **Confidence:** {f.confidence.value}")
            lines.append(f"- **Status:** {f.status.value}")
            lines.append(f"- **Description:** {f.description}")
            lines.append(f"- **Sources:** {len(f.source_observations)} observation(s)")
            lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")