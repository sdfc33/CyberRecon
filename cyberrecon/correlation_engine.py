from cyberrecon.finding import Finding, AttackChain, Severity


def _has(findings: list[Finding], keyword: str) -> list[Finding]:
    return [f for f in findings if keyword.lower() in f.title.lower()]


def correlate(findings: list[Finding]) -> list[AttackChain]:
    chains: list[AttackChain] = []

    targets = {f.target for f in findings}

    for target in targets:
        target_findings = [f for f in findings if f.target == target]

        secrets = _has(target_findings, "secret")
        api_endpoints = _has(target_findings, "API")
        git_exposed = _has(target_findings, "git directory")
        manifests = _has(target_findings, "manifest")

        # Правило A: Secret + API Endpoint
        if secrets and api_endpoints:
            combined = secrets + api_endpoints
            chains.append(
                AttackChain(
                    title="Credential exposure → potential API access",
                    target=target,
                    findings=[f.to_dict() for f in combined],
                    narrative=(
                        f"На {target} одночасно знайдено підозрілий секрет "
                        f"({len(secrets)} шт.) та доступний API endpoint "
                        f"({len(api_endpoints)} шт.). Варто вручну перевірити, "
                        f"чи знайдений токен надає доступ до цього API."
                    ),
                    severity=Severity.HIGH,
                )
            )

        # Правило B: Git exposed + Secret
        if git_exposed and secrets:
            combined = git_exposed + secrets
            chains.append(
                AttackChain(
                    title="Exposed repository likely source of leaked credential",
                    target=target,
                    findings=[f.to_dict() for f in combined],
                    narrative=(
                        f"На {target} відкритий .git-репозиторій та знайдено секрет "
                        f"у JS-файлі. Ймовірно секрет потрапив у білд саме через "
                        f"цей репозиторій — варто перевірити git-історію на предмет "
                        f"інших витоків."
                    ),
                    severity=Severity.HIGH,
                )
            )

        # Правило C: Dependency manifest exposed
        if manifests:
            chains.append(
                AttackChain(
                    title="Technology stack fully mapped",
                    target=target,
                    findings=[f.to_dict() for f in manifests],
                    narrative=(
                        f"На {target} доступний файл-маніфест залежностей — "
                        f"відомі точні версії бібліотек. Рекомендується перевірити "
                        f"версії на osv.dev/NVD на наявність відомих CVE."
                    ),
                    severity=Severity.MEDIUM,
                )
            )

    return chains