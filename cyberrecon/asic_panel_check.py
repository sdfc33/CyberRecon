import httpx
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType

# Найпоширеніші дефолтні креденшели ASIC-прошивок
DEFAULT_CREDENTIALS = [
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "admin"),
]

ASIC_PATHS = ["/", "/cgi-bin/luci", "/cgi-bin/minerStatus.cgi"]


def check_asic_panel(target: str, registry: AssetRegistry, timeout: float = 5.0) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)

    base_url = f"http://{target}"

    reachable = False
    for path in ASIC_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        except httpx.RequestError:
            continue

        if resp.status_code in (200, 401):
            reachable = True
            url_asset = registry.get_or_create(AssetType.URL, url)
            registry.link(domain_asset, url_asset, "serves", source="asic_panel_check")

            if resp.status_code == 401:
                observations.append(
                    Observation(
                        target=target,
                        type="ASIC_PANEL_FOUND",
                        value=url,
                        source="asic_panel_check",
                        evidence={"auth_required": True},
                    )
                )
                for username, password in DEFAULT_CREDENTIALS:
                    try:
                        auth_resp = httpx.get(
                            url, auth=(username, password), timeout=timeout
                        )
                    except httpx.RequestError:
                        continue

                    if auth_resp.status_code == 200:
                        observations.append(
                            Observation(
                                target=target,
                                type="ASIC_DEFAULT_CREDS",
                                value=url,
                                source="asic_panel_check",
                                evidence={"username": username, "password": password},
                            )
                        )
                        break
            else:
                observations.append(
                    Observation(
                        target=target,
                        type="ASIC_PANEL_FOUND",
                        value=url,
                        source="asic_panel_check",
                        evidence={"auth_required": False},
                    )
                )

    return observations