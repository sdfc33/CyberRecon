import subprocess
import json
from pathlib import Path
from cyberrecon.observation import Observation

NUCLEI_PATH = Path("tools") / "nuclei.exe"

# Обмежуємось легкими/швидкими категоріями для першої версії —
# повний набір шаблонів nuclei вміє займати години на один хост
DEFAULT_TAGS = "exposure,misconfig,tech"


def scan_vulnerabilities(target: str, timeout: int = 180) -> list[Observation]:
    observations: list[Observation] = []

    if not NUCLEI_PATH.exists():
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="nuclei.exe not found",
                source="nuclei",
                evidence={"expected_path": str(NUCLEI_PATH)},
            )
        )
        return observations

    url = target if target.startswith("http") else f"https://{target}"

    try:
        result = subprocess.run(
            [
                str(NUCLEI_PATH),
                "-u", url,
                "-tags", DEFAULT_TAGS,
                "-jsonl",
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="nuclei timed out",
                source="nuclei",
                evidence={"timeout": timeout},
            )
        )
        return observations
    except Exception as e:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value=str(e),
                source="nuclei",
                evidence={},
            )
        )
        return observations

    # -jsonl виводить по одному JSON-об'єкту на рядок
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        observations.append(
            Observation(
                target=target,
                type="NUCLEI_MATCH",
                value=item.get("template-id", "unknown"),
                source="nuclei",
                evidence={
                    "name": info.get("name", ""),
                    "severity": info.get("severity", "unknown"),
                    "matched_at": item.get("matched-at", ""),
                    "description": info.get("description", ""),
                },
            )
        )

    return observations