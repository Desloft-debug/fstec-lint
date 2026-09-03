"""Baseline — список уже известных находок, которые не должны валить сборку.

Нужен, чтобы линтер можно было внедрить в существующий проект: текущее
состояние фиксируется один раз, а CI после этого падает только на новых
находках. Формат намеренно простой и отсортированный — файл лежит в
репозитории, и его диффы должны быть читаемыми при ревью.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding

BASELINE_VERSION = 2


class BaselineError(Exception):
    """Baseline-файл отсутствует или испорчен."""


def render(findings: list[Finding]) -> str:
    entries = sorted(
        (
            {
                "rule_id": f.rule.id,
                "file": f.relative_file(),
                "location": f.location,
            }
            for f in findings
        ),
        key=lambda e: (e["rule_id"], e["file"], e["location"]),
    )
    payload = {"version": BASELINE_VERSION, "findings": entries}
    return json.dumps(payload, ensure_ascii=False, indent=2)


def load(path: Path) -> set[str]:
    """Читает baseline и возвращает набор отпечатков находок."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline-файл не найден: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline-файл повреждён ({path}): {exc}") from exc

    version = raw.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"неподдерживаемая версия baseline: {version} (ожидалась {BASELINE_VERSION}) — "
            "перегенерируйте файл через --write-baseline"
        )

    fingerprints = set()
    for entry in raw.get("findings", []):
        fingerprints.add(f"{entry['rule_id']}|{entry['file']}|{entry['location']}")
    return fingerprints


def apply(findings: list[Finding], fingerprints: set[str]) -> tuple[list[Finding], int]:
    """Отсеивает находки из baseline. Возвращает (оставшиеся, сколько подавлено)."""
    remaining = [f for f in findings if f.fingerprint() not in fingerprints]
    return remaining, len(findings) - len(remaining)
