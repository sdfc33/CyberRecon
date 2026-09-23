import httpx
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType

COMMON_MANIFEST_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/composer.lock",
    "/yarn.lock",
    "/requirements.txt",
    "/Gemfile.lock",
    "/Pipfile.lock",
    "/go.sum",
]


def find_exposed_manifests(target: str, registry: AssetRegistry, timeout: float = 5.0) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)
    base_url = f"https://{target}"

    for path in COMMON_MANIFEST_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        except httpx.RequestError:
            continue

        if resp.status_code != 200 or len(resp.text.strip()) < 10:
            continue

        url_asset = registry.get_or_create(AssetType.URL, url)
        registry.link(domain_asset, url_asset, "serves", source="dependencies_check")

        observations.append(
            Observation(
                target=target,
                type="DEPENDENCY_MANIFEST_EXPOSED",
                value=url,
                source="dependencies_check",
                evidence={
                    "status": resp.status_code,
                    "size_bytes": len(resp.text),
                    "snippet": resp.text[:200],
                },
            )
        )

    return observations