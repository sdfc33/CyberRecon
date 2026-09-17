from cyberrecon.observation import Observation
from cyberrecon.finding import Finding, Severity, Confidence, Status

# Мапінг рядкових значень severity від nuclei на нашу enum-модель
_NUCLEI_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def analyze(observations: list[Observation]) -> list[Finding]:
    findings: list[Finding] = []

    for obs in observations:

        # Правило 1: сервер розкриває технологію через заголовок Server
        if obs.type == "HTTP_SERVICE":
            server = obs.evidence.get("server", "unknown")
            if server != "unknown":
                findings.append(
                    Finding(
                        title="Information Disclosure: Server header exposes technology",
                        target=obs.target,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        status=Status.OBSERVED,
                        source_observations=[obs.to_dict()],
                        description=(
                            f"HTTP-відповідь з {obs.value} містить заголовок "
                            f"'Server: {server}', що розкриває технологію сервера."
                        ),
                    )
                )

        # Правило 2: HTTPS недоступний
        if obs.type == "HTTP_UNREACHABLE" and obs.value.startswith("https"):
            findings.append(
                Finding(
                    title="Missing HTTPS support",
                    target=obs.target,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=f"{obs.target} не підтримує HTTPS-з'єднання.",
                )
            )
        # Правило 3: небезпечні незашифровані протоколи
        if obs.type == "OPEN_PORT":
            insecure_services = {"ftp", "telnet", "http"}
            service = obs.evidence.get("service", "").lower()
            if service in insecure_services:
                findings.append(
                    Finding(
                        title=f"Insecure/legacy service exposed: {service}",
                        target=obs.target,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        status=Status.OBSERVED,
                        source_observations=[obs.to_dict()],
                        description=(
                            f"Порт {obs.value} на {obs.target} відкритий і запускає "
                            f"незашифрований/застарілий сервіс '{service}'."
                        ),
                    )
                )
            # Правило 4: знахідки Nuclei
        if obs.type == "NUCLEI_MATCH":
            nuclei_severity = obs.evidence.get("severity", "info").lower()
            severity = _NUCLEI_SEVERITY_MAP.get(nuclei_severity, Severity.INFO)
            name = obs.evidence.get("name", obs.value)

            findings.append(
                Finding(
                    title=name,
                    target=obs.target,
                    severity=severity,
                    confidence=Confidence.MEDIUM,  # автоматичний скан, не перевірено людиною
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"Nuclei template '{obs.value}' спрацював на {obs.evidence.get('matched_at', obs.target)}. "
                        f"{obs.evidence.get('description', '')}"
                    ),
                )
            )
    
            # Правило 5: відкритий .git
        if obs.type == "GIT_EXPOSED":
            findings.append(
                Finding(
                    title="Exposed .git directory",
                    target=obs.target,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"{obs.value} доступний публічно та повертає валідний "
                        f"вміст git-репозиторію — весь вихідний код може бути завантажений."
                    ),
                )
            )

        # Правило 6: підозра на секрет у JS (не підтверджено!)
        if obs.type == "SECRET_MATCH":
            findings.append(
                Finding(
                    title=f"Possible secret exposure: {obs.value}",
                    target=obs.target,
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    status=Status.HYPOTHESIS,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"У файлі {obs.evidence.get('js_file')} regex-патерн "
                        f"'{obs.value}' знайшов можливий секрет. Потребує ручної перевірки — "
                        f"regex дає хибні спрацювання."
                    ),
                )
            )
   
    return findings            