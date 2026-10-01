import os
from dotenv import load_dotenv
from cyberrecon.skill_engine import get_skill_for

load_dotenv()

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


def _build_context(findings: list[dict], chains: list[dict], hypotheses: list[dict]) -> str:
    parts = [
        f"Findings ({len(findings)}):",
        *[f"- [{f['severity']}] {f['title']} (confidence: {f['confidence']}, status: {f['status']})" for f in findings],
        "",
        f"Attack Chains ({len(chains)}):",
        *[f"- [{c['severity']}] {c['title']}: {c['narrative']}" for c in chains],
        "",
        f"Hypotheses ({len(hypotheses)}):",
        *[f"- [{h['vulnerability_type']}] {h['title']}: {h['reasoning']}" for h in hypotheses],
    ]
    return "\n".join(parts)


def _build_skill_context(hypotheses: list[dict]) -> str:
    seen_types = set()
    skill_texts = []

    for h in hypotheses:
        vuln_type = h.get("vulnerability_type", "")
        if vuln_type in seen_types:
            continue
        seen_types.add(vuln_type)

        skill_text = get_skill_for(vuln_type)
        if skill_text:
            skill_texts.append(f"=== Methodology for {vuln_type} ===\n{skill_text}")

    return "\n\n".join(skill_texts)


def generate_ai_summary(
    target: str,
    findings: list[dict],
    chains: list[dict],
    hypotheses: list[dict],
) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        return "AI-аналіз пропущено: ANTHROPIC_API_KEY не знайдено в .env файлі."

    if not ANTHROPIC_AVAILABLE:
        return "AI-аналіз пропущено: бібліотека 'anthropic' не встановлена."

    context = _build_context(findings, chains, hypotheses)
    skill_context = _build_skill_context(hypotheses)

    skill_block = (
        f"\n\nЗастосуй цю експертну методологію при аналізі відповідних гіпотез:\n\n{skill_context}"
        if skill_context
        else ""
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Ти security-аналітик. Ось структуровані дані recon-сканування "
                        f"цілі {target}:\n\n{context}"
                        f"{skill_block}\n\n"
                        f"Напиши висновок: які findings найкритичніші, чи є реальний attack "
                        f"path, з чого почати ручну перевірку (спираючись на методологію вище, "
                        f"де вона застосовна)."
                    ),
                }
            ],
        )
        return response.content[0].text

    except anthropic.AuthenticationError:
        return "AI-аналіз недоступний: невірний API-ключ."
    except anthropic.BadRequestError as e:
        if "credit balance" in str(e).lower():
            return "AI-аналіз недоступний: недостатньо кредитів на балансі Anthropic API."
        return f"AI-аналіз недоступний: некоректний запит ({e})."
    except anthropic.RateLimitError:
        return "AI-аналіз недоступний: перевищено ліміт запитів."
    except anthropic.APIConnectionError:
        return "AI-аналіз недоступний: не вдалось з'єднатись з API (перевір інтернет-з'єднання)."
    except Exception as e:
        return f"AI-аналіз недоступний: неочікувана помилка ({type(e).__name__}: {e})."