from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"

SKILL_MAP = {
    "BOLA/IDOR": "idor.md",
    "Broken Access Control / BOLA / IDOR": "idor.md",
}


def get_skill_for(vulnerability_type: str) -> str | None:
    filename = SKILL_MAP.get(vulnerability_type)
    if not filename:
        return None

    skill_path = SKILLS_DIR / filename
    if not skill_path.exists():
        return None

    return skill_path.read_text(encoding="utf-8")