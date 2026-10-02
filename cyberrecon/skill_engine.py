from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"

SKILL_MAP = {
    "BOLA/IDOR": ["idor.md", "api_security.md"],
    "Broken Access Control / BOLA / IDOR": ["idor.md", "api_security.md"],
    "Dependency/Supply Chain Risk": ["supply_chain.md", "dependency_confusion.md"],
}


def get_skill_for(vulnerability_type: str) -> str | None:
    filenames = SKILL_MAP.get(vulnerability_type)
    if not filenames:
        return None

    texts = []
    for filename in filenames:
        skill_path = SKILLS_DIR / filename
        if skill_path.exists():
            texts.append(skill_path.read_text(encoding="utf-8"))

    if not texts:
        return None

    return "\n\n---\n\n".join(texts)