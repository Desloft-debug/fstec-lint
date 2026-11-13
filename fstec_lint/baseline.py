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
DOCKER_LOCATION = re.compile(r"(?:global|stage .+): (?:ADD|RUN) sha256:[0-9a-f]{64}:[1-9][0-9]*\Z")


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


def _legacy_matches(findings: list[Finding], scan_root: Path) -> dict[str, list[str]]:
    """Reconstruct old addresses only from files selected by the current scan.

    Raw legacy addresses stay local to migration and never enter returned
    fingerprints, reports or diagnostic messages. Ambiguous matches are refused.
    """
    from .checks.dockerfile_checks import REGISTRY, _short, _stages
    from .checks.postgres_checks import _hba_locations
    from .parsers.dockerfile import parse_dockerfile
    from .parsers.postgres import parse_pg_hba

    matches: dict[str, list[str]] = {}
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.rule.id in {"D002", "D005", "P001", "P002"}:
            grouped.setdefault(finding.file, []).append(finding)
    for file, selected in grouped.items():
        source = Path(file)
        old_locations: dict[int, str] = {}
        current_locations: dict[tuple[str, int], str] = {}
        if selected[0].rule.id.startswith("D"):
            instructions = parse_dockerfile(source, scan_root=scan_root)
            for rule_id in {finding.rule.id for finding in selected}:
                for item in REGISTRY[rule_id](instructions):
                    if item[2] is not None:
                        current_locations[rule_id, item[2]] = item[0]
            for stage in _stages(instructions):
                for inst in stage.instructions:
                    if inst["instruction"] in {"ADD", "RUN"}:
                        old_locations[inst["line"]] = (
                            f"{stage.label}: {inst['instruction']} {_short(inst['args'])}"
                        )
        else:
            for record, location in _hba_locations(parse_pg_hba(source, scan_root=scan_root)):
                old_locations[record["line"]] = "pg_hba: " + record["raw"].strip()
                for rule_id in ("P001", "P002"):
                    current_locations[rule_id, record["line"]] = location
        for finding in selected:
            old = old_locations.get(finding.line or 0)
            current = current_locations.get((finding.rule.id, finding.line or 0))
            if old is not None and current == finding.location:
                key = f"{finding.rule.id}|{finding.relative_file().replace(chr(92), '/')}|{old}"
                matches.setdefault(key, []).append(finding.fingerprint())
    return matches


def load(
    path: Path, *, findings: list[Finding] | None = None, scan_root: Path | None = None
) -> set[str]:
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
    legacy: dict[str, list[str]] | None = None
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
        outdated = (
            entry["rule_id"] in {"D002", "D005"}
            and not DOCKER_LOCATION.fullmatch(entry["location"])
        ) or (
            entry["rule_id"] in {"P001", "P002"} and not HBA_LOCATION.fullmatch(entry["location"])
        )
        if outdated:
            if findings is not None and scan_root is not None:
                if legacy is None:
                    try:
                        legacy = _legacy_matches(findings, scan_root)
                    except (OSError, ValueError, UnicodeError):
                        raise BaselineError(
                            "baseline: не удалось проверить старые записи; "
                            "используйте --write-baseline"
                        ) from None
                file = entry["file"].replace("\\", "/")
                candidates = legacy.get(f"{entry['rule_id']}|{file}|{entry['location']}", [])
                if len(candidates) == 1:
                    fingerprints.add(candidates[0])
                    continue
            raise BaselineError(
                "baseline: устаревшая или неоднозначная запись; проверьте находки "
                "и пересоздайте через --write-baseline"
            )
        file = entry["file"].replace("\\", "/")
        fingerprints.add(f"{entry['rule_id']}|{file}|{entry['location']}")
    return fingerprints


def apply(findings: list[Finding], fingerprints: set[str]) -> tuple[list[Finding], int]:
    """Отсеивает находки из baseline. Возвращает (оставшиеся, сколько подавлено)."""
    remaining = [f for f in findings if f.fingerprint() not in fingerprints]
    return remaining, len(findings) - len(remaining)
