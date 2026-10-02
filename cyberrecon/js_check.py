import re
import httpx
from urllib.parse import urljoin
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType
from cyberrecon.url_utils import resolve_scheme

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def find_js_files(target: str, registry: AssetRegistry) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)
    scheme = resolve_scheme(target)
    base_url = f"{scheme}://{target}/"

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
        js_asset = registry.get_or_create(AssetType.JS_FILE, js_url)
        registry.link(domain_asset, js_asset, "serves", source="js_check")

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