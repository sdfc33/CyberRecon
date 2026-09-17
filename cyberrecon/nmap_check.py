import subprocess
import shutil
import xml.etree.ElementTree as ET
from cyberrecon.observation import Observation


def _find_nmap() -> str | None:
    return shutil.which("nmap")


def scan_ports(target: str, timeout: int = 120) -> list[Observation]:
    observations: list[Observation] = []

    nmap_path = _find_nmap()
    if not nmap_path:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="nmap not found in PATH",
                source="nmap",
                evidence={},
            )
        )
        return observations

    try:
        result = subprocess.run(
            [nmap_path, "-sV", "--top-ports", "100", "-oX", "-", target],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="nmap timed out",
                source="nmap",
                evidence={"timeout": timeout},
            )
        )
        return observations
    except Exception as e:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value=str(e),
                source="nmap",
                evidence={},
            )
        )
        return observations

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        observations.append(
            Observation(
                target=target,
                type="TOOL_ERROR",
                value="failed to parse nmap XML output",
                source="nmap",
                evidence={},
            )
        )
        return observations

    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = port.get("portid")
            protocol = port.get("protocol")
            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product") if service_el is not None else ""
            version = service_el.get("version") if service_el is not None else ""

            observations.append(
                Observation(
                    target=target,
                    type="OPEN_PORT",
                    value=f"{protocol}/{portid}",
                    source="nmap",
                    evidence={
                        "service": service_name,
                        "product": product,
                        "version": version,
                    },
                )
            )

    return observations