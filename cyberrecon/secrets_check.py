import re
import httpx
from cyberrecon.observation import Observation

# Мінімальний набір патернів для першої версії — розширюваний список
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r"api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", re.IGNORECASE),
    "Bearer Token": re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
}


def scan_js_for_secrets(js_observations: list[Observation]) -> list[Observation]:
    observations: list[Observation] = []

    for obs in js_observations:
        if obs.type != "JS_FILE":
            continue

        try:
            resp = httpx.get(obs.value, timeout=5.0)
        except httpx.RequestError:
            continue

        for name, pattern in SECRET_PATTERNS.items():
            match = pattern.search(resp.text)
            if match:
                observations.append(
                    Observation(
                        target=obs.target,
                        type="SECRET_MATCH",
                        value=name,
                        source="secrets_check",
                        evidence={
                            "js_file": obs.value,
                            "matched_snippet": match.group(0)[:40] + "...",
                        },
                    )
                )

    return observations