"""Baseline — список уже известных находок, которые не должны валить сборку.

Нужен, чтобы линтер можно было внедрить в существующий проект: текущее
состояние фиксируется один раз, а CI после этого падает только на новых
находках. Формат намеренно простой и отсортированный — файл лежит в
репозитории, и его диффы должны быть читаемыми при ревью.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding

# 3: адрес D002/D005 при усечении получил хвост-хеш полного текста
# команды — две длинные команды с общим началом делили один адрес.
# Отпечатки изменились, baseline от 0.8.x надо перегенерировать.
BASELINE_VERSION = 3
REQUIRED_FIELDS = frozenset({"rule_id", "file", "location"})
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_ENTRIES = 10_000
MAX_FIELD_LENGTH = 65_536
HBA_LOCATION = re.compile(r"pg_hba:v2:[0-9a-f]{64}:[1-9][0-9]*\Z")


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
        with path.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise BaselineError("baseline: превышен предел размера")
        text = data.decode("utf-8")
        depth = 0
        in_string = False
        escaped = False
        for char in text:
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise BaselineError("baseline: превышен предел вложенности")
            elif char in "]}":
                depth -= 1
        raw = json.loads(text)
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline-файл не найден: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline-файл повреждён ({path}): ошибка JSON в строке {exc.lineno}, "
            f"столбце {exc.colno}"
        ) from exc
    except (RecursionError, ValueError) as exc:
        raise BaselineError(f"baseline-файл повреждён ({path}): недопустимый JSON") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise BaselineError(f"baseline-файл недоступен или не является UTF-8 ({path})") from exc

    # Файл лежит в репозитории и правится руками, поэтому «синтаксически
    # верный, но не той формы» — обычный случай, а не экзотика. Он должен
    # приводить к понятной ошибке и коду 2, а не к трейсбеку.
    if not isinstance(raw, dict):
        raise BaselineError(
            f"baseline-файл повреждён ({path}): ожидался объект JSON, "
            f"получен {type(raw).__name__} — перегенерируйте файл через --write-baseline"
        )

    version = raw.get("version")
    if type(version) is not int or version != BASELINE_VERSION:
        raise BaselineError(
            f"неподдерживаемая версия baseline (ожидалась {BASELINE_VERSION}) — "
            "перегенерируйте файл через --write-baseline"
        )

    entries = raw.get("findings", [])
    if not isinstance(entries, list):
        raise BaselineError(
            f"baseline-файл повреждён ({path}): поле 'findings' должно быть списком — "
            "перегенерируйте файл через --write-baseline"
        )
    if len(entries) > MAX_ENTRIES:
        raise BaselineError("baseline: превышен предел числа записей")

    fingerprints = set()
    for entry in entries:
        if not isinstance(entry, dict) or not REQUIRED_FIELDS <= entry.keys():
            raise BaselineError(
                f"baseline-файл повреждён ({path}): запись без обязательных полей "
                f"{', '.join(sorted(REQUIRED_FIELDS))} — "
                "перегенерируйте файл через --write-baseline"
            )
        if any(
            not isinstance(entry[key], str) or len(entry[key]) > MAX_FIELD_LENGTH
            for key in REQUIRED_FIELDS
        ):
            raise BaselineError(
                "baseline: недопустимые поля записи — пересоздайте через --write-baseline"
            )
        if entry["rule_id"] in {"D002", "D005"} and not re.fullmatch(
            r"(?:global|stage .+): (?:ADD|RUN) instruction:[1-9][0-9]*", entry["location"]
        ):
            raise BaselineError(
                "baseline: устаревшая Docker-запись; проверьте находки и пересоздайте "
                "через --write-baseline"
            )
        if entry["rule_id"] in {"P001", "P002"} and not HBA_LOCATION.fullmatch(entry["location"]):
            raise BaselineError(
                "baseline: устаревшая или недопустимая HBA-запись; "
                "явно пересоздайте через --write-baseline"
            )
        fingerprints.add(f"{entry['rule_id']}|{entry['file']}|{entry['location']}")
    return fingerprints


def apply(findings: list[Finding], fingerprints: set[str]) -> tuple[list[Finding], int]:
    """Отсеивает находки из baseline. Возвращает (оставшиеся, сколько подавлено)."""
    # An ordinal cannot distinguish a replacement instruction from the one
    # previously accepted. Do not suppress ambiguous Docker commands: storing
    # their contents or a guessable digest can expose embedded credentials.
    remaining = [
        f for f in findings if f.rule.id in {"D002", "D005"} or f.fingerprint() not in fingerprints
    ]
    return remaining, len(findings) - len(remaining)
