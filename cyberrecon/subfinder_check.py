import subprocess
from pathlib import Path
from cyberrecon.observation import Observation

SUBFINDER_PATH = Path("tools") / "subfinder.exe"


def find_subdomains(target: str, timeout: int = 60) -> list[Observation]:
    observations: list[Observation] = []

    if not SUBFINDER_PATH.exists():
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="subfinder.exe not found",
                source="subfinder",
                evidence={"expected_path": str(SUBFINDER_PATH)},
            )
        )
        return observations

    try:
        result = subprocess.run(
            [str(SUBFINDER_PATH), "-d", target, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="subfinder timed out",
                source="subfinder",
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
                source="subfinder",
                evidence={},
            )
        )
        return observations

    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    for sub in subdomains:
        observations.append(
            Observation(
                target=target,
                type="SUBDOMAIN",
                value=sub,
                source="subfinder",
                evidence={},
            )
        )

    return observations