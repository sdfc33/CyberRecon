from cyberrecon.finding import Finding, Confidence
from cyberrecon.hypothesis import Hypothesis


def generate_hypotheses(findings: list[Finding]) -> list[Hypothesis]:
    hypotheses: list[Hypothesis] = []

    api_findings = [
        f for f in findings
        if "API" in f.title or "api" in f.title.lower()
    ]

    for f in api_findings:
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

    return hypotheses