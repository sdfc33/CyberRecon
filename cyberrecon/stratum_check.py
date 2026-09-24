import socket
import json
from cyberrecon.observation import Observation
from cyberrecon.asset import AssetRegistry, AssetType

DEFAULT_STRATUM_PORTS = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 13333, 15555, 17777, 23333]


def _try_stratum_handshake(host: str, port: int, timeout: float) -> dict | None:
    """Пробує надіслати справжній stratum mining.subscribe запит і прочитати відповідь."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = json.dumps({
                "id": 1,
                "method": "mining.subscribe",
                "params": ["cyberrecon/0.1"],
            }) + "\n"
            sock.sendall(request.encode())

            response_raw = sock.recv(4096).decode(errors="replace").strip()
            if not response_raw:
                return None

            try:
                parsed = json.loads(response_raw.splitlines()[0])
            except json.JSONDecodeError:
                return {"raw": response_raw[:200], "parsed": False}

            return {"raw": response_raw[:200], "parsed": True, "response": parsed}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_mining_ports(
    target: str,
    registry: AssetRegistry,
    ports: list[int] = None,
    timeout: float = 3.0,
) -> list[Observation]:
    observations: list[Observation] = []
    domain_asset = registry.get_or_create(AssetType.DOMAIN, target)
    ports_to_scan = ports or DEFAULT_STRATUM_PORTS

    for port in ports_to_scan:
        try:
            with socket.create_connection((target, port), timeout=timeout):
                port_open = True
        except (socket.timeout, ConnectionRefusedError, OSError):
            port_open = False

        if not port_open:
            continue

        port_value = f"tcp/{port}"
        port_asset = registry.get_or_create(AssetType.PORT, port_value)
        registry.link(domain_asset, port_asset, "has_port", source="stratum_check")

        handshake = _try_stratum_handshake(target, port, timeout)

        if handshake and handshake.get("parsed"):
            observations.append(
                Observation(
                    target=target,
                    type="STRATUM_EXPOSED",
                    value=port_value,
                    source="stratum_check",
                    evidence={
                        "confirmed": True,
                        "response_snippet": handshake["raw"],
                    },
                )
            )
        else:
            observations.append(
                Observation(
                    target=target,
                    type="MINING_PORT_OPEN",
                    value=port_value,
                    source="stratum_check",
                    evidence={
                        "confirmed": False,
                        "note": "Порт відкритий, але stratum-handshake не підтвердився — "
                                "можливо інший сервіс на цьому порту.",
                    },
                )
            )

    return observations