import httpx
from cyberrecon.observation import Observation


def check_git_exposure(target: str) -> list[Observation]:
    observations: list[Observation] = []
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

    # Справжній .git/HEAD завжди починається з "ref: refs/"
    if resp.status_code == 200 and resp.text.strip().startswith("ref:"):
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