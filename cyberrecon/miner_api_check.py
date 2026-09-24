import socket
import json
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType

DEFAULT_MINER_API_PORT = 4028


def _query_miner_api(host: str, port: int, command: str, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = json.dumps({"command": command})
            sock.sendall(request.encode())

            response_raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_raw += chunk
                if len(response_raw) > 65536:
                    break

            cleaned = response_raw.decode(errors="replace").rstrip("\x00\n")
            return json.loads(cleaned)
    except (socket.timeout, ConnectionRefusedError, OSError, json.JSONDecodeError):
        return None


def check_miner_api(
    target: str, registry: AssetRegistry, port: int = DEFAULT_MINER_API_PORT, timeout: float = 3.0
) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)

    result = _query_miner_api(target, port, "version", timeout)

    if result is not None:
        port_value = f"tcp/{port}"
        port_asset = registry.get_or_create(AssetType.PORT, port_value)
        registry.link(domain_asset, port_asset, "has_port", source="miner_api_check")

        observations.append(
            Observation(
                target=target,
                type="MINER_API_EXPOSED",
                value=port_value,
                source="miner_api_check",
                evidence={"response": result},
            )
        )

    return observations