from cyberrecon.hypothesis import Hypothesis
from cyberrecon.validation_plan import ValidationPlan


def _plan_for_bola(hyp: Hypothesis) -> ValidationPlan:
    return ValidationPlan(
        hypothesis_title=hyp.title,
        target=hyp.target,
        steps=[
            "Автентифікуйся під власним тестовим акаунтом (User A).",
            "Знайди запит, що звертається до конкретного об'єкта за ID "
            "(наприклад GET /api/orders/123).",
            "Збережи цей запит і відповідь як базову точку відліку (baseline).",
            "Створи другий тестовий акаунт (User B), отримай його токен/сесію.",
            "Тим самим запитом, але з токеном User B, зверни увагу на об'єкт, "
            "що належить User A (той самий ID 123).",
            "Порівняй відповідь: якщо User B отримав дані User A — авторизація "
            "не перевіряється на рівні об'єкта.",
            "Повтори з декрементованим/інкрементованим ID (122, 124) без токена "
            "взагалі, щоб перевірити ще й неавтентифікований доступ.",
            "Зроби скріншоти/HTTP-логи кожного кроку — вони потрібні як PoC.",
        ],
        tools_needed=["Burp Suite (або curl/Postman)", "Два тестові акаунти"],
        caution=(
            "Використовуй ЛИШЕ власні тестові акаунти. Не звертайся до об'єктів "
            "реальних користувачів навіть для перевірки — це вже вихід за межі "
            "дозволеного тестування навіть у межах bug bounty scope."
        ),
    )


def generate_validation_plans(hypotheses: list[Hypothesis]) -> list[ValidationPlan]:
    plans: list[ValidationPlan] = []

    for hyp in hypotheses:
        if "BOLA" in hyp.vulnerability_type or "IDOR" in hyp.vulnerability_type:
            plans.append(_plan_for_bola(hyp))

    return plans