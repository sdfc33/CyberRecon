from cyberrecon.finding import Finding, Confidence
from cyberrecon.hypothesis import Hypothesis


def _findings_with(findings: list[Finding], keyword: str) -> list[Finding]:
    return [f for f in findings if keyword.lower() in f.title.lower()]


def generate_hypotheses(findings: list[Finding]) -> list[Hypothesis]:
    hypotheses: list[Hypothesis] = []

    # Правило 1: API endpoint без підтвердженої авторизації
    for f in _findings_with(findings, "API"):
        hypotheses.append(
            Hypothesis(
                title=f"Unverified authorization on {f.target}",
                target=f.target,
                vulnerability_type="Broken Access Control / BOLA / IDOR",
                reasoning=(
                    f"Знайдено доступний API endpoint ({f.title}), але CyberRecon "
                    f"не перевіряє наявність авторизації (пасивний recon, не активне "
                    f"тестування). Відсутність підтвердження авторизації — не доказ "
                    f"її відсутності, але привід перевірити вручну: спробувати запит "
                    f"без токена, з чужим токеном, зі зміненим object ID."
                ),
                supporting_findings=[f.to_dict()],
                confidence=Confidence.LOW,
            )
        )

    # Правило 2: знайдений секрет — чи він активний?
    for f in _findings_with(findings, "secret"):
        hypotheses.append(
            Hypothesis(
                title=f"Possible active credential on {f.target}",
                target=f.target,
                vulnerability_type="Credential Exposure",
                reasoning=(
                    f"Знайдено підозрілий секрет у JS-коді ({f.title}). Regex-пошук "
                    f"підтверджує лише формат рядка, не його чинність. Потребує "
                    f"перевірки: чи ключ досі активний, до якого сервісу/акаунта "
                    f"надає доступ, і чи не є він прикладом з документації/тестовим."
                ),
                supporting_findings=[f.to_dict()],
                confidence=Confidence.LOW,
            )
        )

    # Правило 3: відкритий .git — можливі додаткові секрети в історії
    for f in _findings_with(findings, "git directory"):
        hypotheses.append(
            Hypothesis(
                title=f"Additional secrets may exist in git history on {f.target}",
                target=f.target,
                vulnerability_type="Source Code Exposure",
                reasoning=(
                    f"Відкритий .git-репозиторій ({f.title}) дозволяє завантажити "
                    f"повну історію комітів, не лише поточний стан файлів. Секрети, "
                    f"видалені в пізніших комітах, часто лишаються доступні в історії. "
                    f"Варто клонувати репозиторій і перевірити git log/git diff на "
                    f"видалені credentials."
                ),
                supporting_findings=[f.to_dict()],
                confidence=Confidence.MEDIUM,
            )
        )

    # Правило 4: відкритий Stratum — можливість неавторизованого підключення
    for f in _findings_with(findings, "stratum"):
        hypotheses.append(
            Hypothesis(
                title=f"Unauthorized mining pool access possible on {f.target}",
                target=f.target,
                vulnerability_type="Mining Infrastructure Unauthorized Access",
                reasoning=(
                    f"Stratum-сервіс ({f.title}) відповів на mining.subscribe без "
                    f"автентифікації на рівні TCP-з'єднання. Це не доводить відсутність "
                    f"авторизації на рівні воркера (worker credentials можуть "
                    f"перевірятись на наступному кроці — mining.authorize). Варто "
                    f"перевірити, чи приймається довільне ім'я воркера."
                ),
                supporting_findings=[f.to_dict()],
                confidence=Confidence.LOW,
            )
        )

    # Правило 5: публічно доступний маніфест залежностей
    for f in _findings_with(findings, "manifest"):
        hypotheses.append(
            Hypothesis(
                title=f"Dependency/supply chain risk on {f.target}",
                target=f.target,
                vulnerability_type="Dependency/Supply Chain Risk",
                reasoning=(
                    f"Публічно доступний файл-маніфест залежностей ({f.title}) розкриває "
                    f"точні версії бібліотек і, можливо, назви внутрішніх/приватних пакетів. "
                    f"Варто перевірити версії на відомі CVE (osv.dev/NVD) та перевірити, "
                    f"чи немає серед залежностей приватних імен пакетів, вразливих до "
                    f"dependency confusion (чи існує публічний пакет з такою ж назвою)."
                ),
                supporting_findings=[f.to_dict()],
                confidence=Confidence.LOW,
            )
        )

    return hypotheses