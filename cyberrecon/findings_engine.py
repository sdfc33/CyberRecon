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

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CONFIDENCE_ORDER = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
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
                    confidence=Confidence.MEDIUM,
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

        # Правило 7: публічно доступна API-документація/ендпоінт
        if obs.type == "API_ENDPOINT":
            looks_like_doc = obs.evidence.get("looks_like_doc", False)
            findings.append(
                Finding(
                    title=(
                        "Exposed API documentation"
                        if looks_like_doc
                        else "Accessible API endpoint"
                    ),
                    target=obs.target,
                    severity=Severity.LOW if looks_like_doc else Severity.INFO,
                    confidence=Confidence.HIGH if looks_like_doc else Confidence.MEDIUM,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"{obs.value} публічно доступний (статус {obs.evidence.get('status')}). "
                        f"Розширює відому поверхню атаки — варто перевірити на відсутність "
                        f"авторизації для чутливих ендпоінтів."
                    ),
                )
            )
        
         # Правило 8: публічно доступний файл-маніфест залежностей
        if obs.type == "DEPENDENCY_MANIFEST_EXPOSED":
            findings.append(
                Finding(
                    title="Exposed dependency manifest file",
                    target=obs.target,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"{obs.value} публічно доступний і розкриває точні версії "
                        f"використаних бібліотек — варто вручну перевірити версії "
                        f"на наявність відомих CVE (наприклад через osv.dev)."
                    ),
                )
            )

        # Правило 9: підтверджений відкритий Stratum-сервіс
        if obs.type == "STRATUM_EXPOSED":
            findings.append(
                Finding(
                    title="Unauthenticated Stratum mining interface exposed",
                    target=obs.target,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"Stratum-сервіс на {obs.target}:{obs.value} відповів на "
                        f"mining.subscribe без будь-якої автентифікації на рівні "
                        f"TCP-з'єднання. Варто перевірити, чи можна підключити "
                        f"сторонній майнер до цього пулу без авторизації."
                    ),
                )
            )

        # Правило 10: відкритий mining-порт без підтвердженого протоколу
        if obs.type == "MINING_PORT_OPEN":
            findings.append(
                Finding(
                    title="Unidentified service on typical mining port",
                    target=obs.target,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    status=Status.HYPOTHESIS,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"Порт {obs.value} на {obs.target} відкритий, але не "
                        f"вдалось підтвердити stratum-протокол. Потребує ручної "
                        f"перевірки — можливо, інший сервіс або нестандартна "
                        f"реалізація stratum."
                    ),
                )
            )

                # Правило 11: знайдено ASIC-панель (з авторизацією чи без)
        if obs.type == "ASIC_PANEL_FOUND":
            auth_required = obs.evidence.get("auth_required", True)
            findings.append(
                Finding(
                    title=(
                        "ASIC management panel without authentication"
                        if not auth_required
                        else "ASIC management panel found"
                    ),
                    target=obs.target,
                    severity=Severity.HIGH if not auth_required else Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"Веб-панель керування ASIC знайдено на {obs.value}. "
                        f"{'Доступ БЕЗ автентифікації взагалі.' if not auth_required else 'Вимагає автентифікацію.'}"
                    ),
                )
            )

        # Правило 12: дефолтні креденшели спрацювали
        if obs.type == "ASIC_DEFAULT_CREDS":
            findings.append(
                Finding(
                    title="Default credentials work on ASIC panel",
                    target=obs.target,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    status=Status.CONFIRMED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"Дефолтні креденшели ({obs.evidence.get('username')}/"
                        f"{obs.evidence.get('password')}) успішно спрацювали на "
                        f"{obs.value}. Повний доступ до керування пристроєм."
                    ),
                )
            )

        # Правило 13: відкритий miner API без авторизації
        if obs.type == "MINER_API_EXPOSED":
            findings.append(
                Finding(
                    title="Unauthenticated miner API exposed",
                    target=obs.target,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=Status.OBSERVED,
                    source_observations=[obs.to_dict()],
                    description=(
                        f"cgminer/bmminer API на {obs.target}:{obs.value} відповідає "
                        f"без автентифікації. Залежно від прошивки, може дозволяти "
                        f"команди керування (restart, config change), не лише перегляд стану."
                    ),
                )
            )

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        key = (f.title, f.target)
        grouped.setdefault(key, []).append(f)

    deduped: list[Finding] = []
    for (title, target), group in grouped.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        all_observations = []
        for f in group:
            all_observations.extend(f.source_observations)

        best_severity = max(group, key=lambda f: _SEVERITY_ORDER[f.severity]).severity
        best_confidence = max(group, key=lambda f: _CONFIDENCE_ORDER[f.confidence]).confidence

        merged = Finding(
            title=title,
            target=target,
            severity=best_severity,
            confidence=best_confidence,
            status=group[0].status,
            source_observations=all_observations,
            description=(
                f"{group[0].description} "
                f"(знайдено {len(group)} разів на різних джерелах — деталі в source_observations)"
            ),
        )
        deduped.append(merged)

    return deduped