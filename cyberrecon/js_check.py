import re
import httpx
from urllib.parse import urljoin
from cyberrecon.observation import Observation

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def find_js_files(target: str) -> list[Observation]:
    observations: list[Observation] = []
    base_url = f"https://{target}/"

    try:
        resp = httpx.get(base_url, timeout=5.0, follow_redirects=True)
    except httpx.RequestError as e:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value=str(e),
                source="js_check",
                evidence={"url": base_url},
            )
        )
        return observations

    raw_links = SCRIPT_SRC_RE.findall(resp.text)
    js_urls = {urljoin(str(resp.url), link) for link in raw_links if link.endswith(".js")}

    for js_url in js_urls:
        observations.append(
            Observation(
                target=target,
                type="JS_FILE",
                value=js_url,
                source="js_check",
                evidence={},
            )
        )

    return observations