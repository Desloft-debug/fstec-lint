"""Baseline: известные находки, которые не должны ронять сборку.

Текущее состояние фиксируется один раз, дальше CI падает только на новых
находках. Файл отсортирован, чтобы диффы в ревью читались.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding

# v3: к усечённому адресу D002/D005 добавлен хеш команды.
# Baseline от 0.8.x нужно перегенерировать.
BASELINE_VERSION = 3
REQUIRED_FIELDS = frozenset({"rule_id", "file", "location"})


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

    # Файл правят руками, поэтому неверная структура — ожидаемая ошибка
    # (код 2), а не трейсбек.
    if not isinstance(raw, dict):
        raise BaselineError(
            f"baseline-файл повреждён ({path}): ожидался объект JSON, "
            f"получен {type(raw).__name__} — перегенерируйте файл через --write-baseline"
        )

    version = raw.get("version")
    if version != BASELINE_VERSION:
        raise BaselineError(
            f"неподдерживаемая версия baseline: {version} (ожидалась {BASELINE_VERSION}) — "
            "перегенерируйте файл через --write-baseline"
        )

    entries = raw.get("findings", [])
    if not isinstance(entries, list):
        raise BaselineError(
            f"baseline-файл повреждён ({path}): поле 'findings' должно быть списком — "
            "перегенерируйте файл через --write-baseline"
        )

    fingerprints = set()
    for entry in entries:
        if not isinstance(entry, dict) or not REQUIRED_FIELDS <= entry.keys():
            raise BaselineError(
                f"baseline-файл повреждён ({path}): запись без обязательных полей "
                f"{', '.join(sorted(REQUIRED_FIELDS))}: {entry!r} — "
                "перегенерируйте файл через --write-baseline"
            )
        fingerprints.add(f"{entry['rule_id']}|{entry['file']}|{entry['location']}")
    return fingerprints


def apply(findings: list[Finding], fingerprints: set[str]) -> tuple[list[Finding], int]:
    """Отсеивает находки из baseline. Возвращает (оставшиеся, сколько подавлено)."""
    remaining = [f for f in findings if f.fingerprint() not in fingerprints]
    return remaining, len(findings) - len(remaining)
