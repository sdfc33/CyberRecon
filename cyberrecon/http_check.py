import httpx
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType


def check_http(target: str, registry: AssetRegistry) -> list[Observation]:
    observations = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)

    for scheme in ("http", "https"):
        url = f"{scheme}://{target}"
        try:
            resp = httpx.get(url, timeout=5.0, follow_redirects=True)

            url_asset = registry.get_or_create(AssetType.URL, url)
            registry.link(domain_asset, url_asset, "serves", source="http_check")

            observations.append(
                Observation(
                    target=target,
                    type="HTTP_SERVICE",
                    value=url,
                    source="httpx",
                    evidence={
                        "status": resp.status_code,
                        "final_url": str(resp.url),
                        "server": resp.headers.get("server", "unknown"),
                    },
                )
            )
        except httpx.RequestError as e:
            observations.append(
                Observation(
                    target=target,
                    type="HTTP_UNREACHABLE",
                    value=url,
                    source="httpx",
                    evidence={"error": str(e)},
                )
            )
    return observations