import httpx
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType

# Типові шляхи, де публікується API-документація або сам API
COMMON_API_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/swagger.json",
    "/api/v1/swagger.json",
    "/.well-known/openapi.yaml",
    "/graphql",
    "/api/v1",
    "/api/v2",
]

# Ключові слова, які підтверджують, що це справді API-специфікація,
# а не просто випадкова 200-сторінка (наприклад, кастомна 404)
DOC_INDICATORS = ("swagger", "openapi", "\"paths\"", "graphql")


def find_api_endpoints(target: str, registry: AssetRegistry, timeout: float = 5.0) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)
    base_url = f"https://{target}"

    for path in COMMON_API_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        except httpx.RequestError:
            continue

        if resp.status_code != 200:
            continue

        body_lower = resp.text[:2000].lower()
        is_doc = any(indicator in body_lower for indicator in DOC_INDICATORS)

        url_asset = registry.get_or_create(AssetType.URL, url)
        registry.link(domain_asset, url_asset, "serves", source="api_check")

        observations.append(
            Observation(
                target=target,
                type="API_ENDPOINT",
                value=url,
                source="api_check",
                evidence={
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", "unknown"),
                    "looks_like_doc": is_doc,
                },
            )
        )

    return observations