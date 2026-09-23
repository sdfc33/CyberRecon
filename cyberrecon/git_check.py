import httpx
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType


def check_git_exposure(target: str, registry: AssetRegistry) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)
    url = f"https://{target}/.git/HEAD"

    try:
        resp = httpx.get(url, timeout=5.0, follow_redirects=False)
    except httpx.RequestError as e:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value=str(e),
                source="git_check",
                evidence={"url": url},
            )
        )
        return observations

    if resp.status_code == 200 and resp.text.strip().startswith("ref:"):
        url_asset = registry.get_or_create(AssetType.URL, url)
        registry.link(domain_asset, url_asset, "serves", source="git_check")

        observations.append(
            Observation(
                target=target,
                type="GIT_EXPOSED",
                value=url,
                source="git_check",
                evidence={"status": resp.status_code, "content": resp.text.strip()},
            )
        )

    return observations