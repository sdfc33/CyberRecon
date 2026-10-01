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


def _plan_for_credential_exposure(hyp: Hypothesis) -> ValidationPlan:
    return ValidationPlan(
        hypothesis_title=hyp.title,
        target=hyp.target,
        steps=[
            "Визнач тип секрету за форматом (AWS ключ, Bearer token, generic API key тощо).",
            "Перевір, чи це приклад з документації/тестовий заглушка (часто містить "
            "слова test/example/dummy або явно невалідний формат).",
            "Для AWS-подібних ключів: спробуй безпечну read-only команду "
            "(наприклад aws sts get-caller-identity) — вона лише підтверджує "
            "валідність, не змінює нічого.",
            "Для Bearer/API token: спробуй мінімально інвазивний GET-запит до "
            "відповідного API (наприклад /me чи /user/profile), щоб перевірити "
            "активність без зміни даних.",
            "Якщо ключ активний — НЕГАЙНО задокументуй (скріншот відповіді, timestamp) "
            "і повідом про нього в межах bug bounty програми, не продовжуй подальше "
            "використання.",
            "Зафіксуй, звідки саме секрет потрапив у публічний доступ (JS-файл, URL).",
        ],
        tools_needed=["curl/Postman", "AWS CLI (якщо AWS-ключ)"],
        caution=(
            "НЕ використовуй знайдений ключ для дій, що змінюють дані чи стан системи "
            "(write/delete операції). Мета — підтвердити активність, а не отримати "
            "доступ до функціоналу. Негайно повідом про знахідку власнику/програмі."
        ),
    )


def _plan_for_source_exposure(hyp: Hypothesis) -> ValidationPlan:
    return ValidationPlan(
        hypothesis_title=hyp.title,
        target=hyp.target,
        steps=[
            "Клонуй відкритий репозиторій: git clone http://<target>/.git/ local-copy "
            "(або скористайся спеціалізованим інструментом типу git-dumper).",
            "Перевір git log --all --oneline на наявність комітів з назвами на кшталт "
            "'remove secret', 'fix credentials', 'oops'.",
            "Запусти пошук секретів по всій історії: gitleaks detect --source=local-copy "
            "або trufflehog git file://local-copy.",
            "Перевір .git/config на наявність внутрішніх URL (staging/internal сервери).",
            "Задокументуй знайдене з точними git hash комітів як доказ.",
        ],
        tools_needed=["git", "gitleaks або trufflehog"],
        caution=(
            "Завантажений код може містити конфіденційну бізнес-логіку — не "
            "розповсюджуй і не публікуй отриманий код, навіть у звіті (лише "
            "конкретні знайдені секрети/факти, не весь репозиторій)."
        ),
    )


def _plan_for_mining_unauthorized_access(hyp: Hypothesis) -> ValidationPlan:
    return ValidationPlan(
        hypothesis_title=hyp.title,
        target=hyp.target,
        steps=[
            "Підключись до stratum-порту вручну (telnet/nc або скрипт) і надішли "
            "mining.subscribe.",
            "Спробуй mining.authorize з довільним/вигаданим worker-ім'ям і будь-яким паролем.",
            "Зафіксуй, чи сервер прийняв авторизацію (true) чи відхилив (false).",
            "Якщо прийняв — спробуй надіслати валідний share (потребує реального "
            "майнінг-клієнта, напр. cpuminer, спрямованого на цей stratum).",
            "Задокументуй повну відповідь сервера на кожному кроці як доказ.",
        ],
        tools_needed=["netcat/telnet", "cpuminer або аналогічний легкий майнер-клієнт"],
        caution=(
            "Виконуй ЛИШЕ на власному тестовому стенді. Підключення стороннього "
            "майнера до чужого пулу без дозволу — це несанкціонований доступ, "
            "навіть якщо технічно можливий."
        ),
    )


_PLAN_DISPATCH = {
    "BOLA": _plan_for_bola,
    "IDOR": _plan_for_bola,
    "Credential Exposure": _plan_for_credential_exposure,
    "Source Code Exposure": _plan_for_source_exposure,
    "Mining Infrastructure Unauthorized Access": _plan_for_mining_unauthorized_access,
}


def generate_validation_plans(hypotheses: list[Hypothesis]) -> list[ValidationPlan]:
    plans: list[ValidationPlan] = []

    for hyp in hypotheses:
        for keyword, plan_func in _PLAN_DISPATCH.items():
            if keyword in hyp.vulnerability_type:
                plans.append(plan_func(hyp))
                break

    return plans