import httpx


def resolve_scheme(target: str, timeout: float = 3.0) -> str:
    """Пробує HTTPS; якщо недоступний — повертає HTTP як запасний варіант."""
    try:
        httpx.get(f"https://{target}", timeout=timeout)
        return "https"
    except httpx.RequestError:
        return "http"