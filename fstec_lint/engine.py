from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks import compose_checks, dockerfile_checks, postgres_checks, sshd_checks, systemd_checks
from .checks.base import CheckResult, CheckResults
from .models import Finding, Rule, Severity
from .parsers.compose import parse_compose
from .parsers.dockerfile import parse_dockerfile
from .parsers.postgres import parse_pg_hba, parse_postgresql_conf
from .parsers.sshd import parse_sshd_config
from .parsers.systemd import parse_systemd_unit

RULES_DIR = Path(__file__).parent / "rules"

COMPOSE_FILE_PATTERNS = (
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose.yml",
    "compose.yaml",
)
POSTGRESQL_CONF_PATTERNS = ("postgresql.conf",)
PG_HBA_PATTERNS = ("pg_hba.conf",)
SSHD_CONFIG_PATTERNS = ("sshd_config",)
SYSTEMD_UNIT_PATTERNS = ("*.service",)
DOCKERFILE_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.dockerfile")

# Каталоги со сторонним и служебным содержимым: конфиги внутри них не
# наши и правятся не нами, а на большом репозитории они дают основную
# массу шума и времени обхода.
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
    }
)

CheckFn = Callable[[Any], CheckResults]

# Подавление находки прямо в проверяемом файле: комментарий действует на
# свою строку и на следующую, чтобы его можно было писать и в хвосте
# строки, и над ней (в YAML хвост не всегда читаем).
#   ports: ["5432:5432"]  # fstec-lint: ignore C005
#   # fstec-lint: ignore
SUPPRESSION_RE = re.compile(r"fstec-lint:\s*ignore(?P<rules>[A-Za-z0-9,*\s]*)", re.IGNORECASE)


@dataclass(frozen=True)
class ScanError:
    """Файл, который не удалось разобрать: битый синтаксис, не UTF-8, нет прав."""

    file: str
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    suppressed: int = 0


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules: list[Rule] = []
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or []
        for item in raw:
            rules.append(
                Rule(
                    id=item["id"],
                    title=item["title"],
                    severity=Severity.from_str(item["severity"]),
                    measure=item["measure"],
                    measure_title=item.get("measure_title", ""),
                    description=" ".join(item["description"].split()),
                    remediation=" ".join(item["remediation"].split()),
                    target=item["target"],
                    orders=item.get("orders", ""),
                    legacy_measure=item.get("legacy_measure", ""),
                )
            )
    return rules


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _matches_rule(rule_id: str, patterns: Iterable[str]) -> bool:
    """Правило задаётся id или glob-ом: C001, C*, ?00*. Регистр не важен."""
    return any(fnmatch.fnmatch(rule_id.upper(), pattern.upper()) for pattern in patterns)


def filter_rules(
    rules: list[Rule], select: Sequence[str] = (), ignore: Sequence[str] = ()
) -> list[Rule]:
    """Оставляет правила из --select (если он задан) минус правила из --ignore."""
    if select:
        rules = [rule for rule in rules if _matches_rule(rule.id, select)]
    if ignore:
        rules = [rule for rule in rules if not _matches_rule(rule.id, ignore)]
    return rules


def unknown_patterns(rules: list[Rule], patterns: Sequence[str]) -> list[str]:
    """Шаблоны, не подошедшие ни к одному правилу, — обычно это опечатка."""
    return [p for p in patterns if not any(_matches_rule(rule.id, [p]) for rule in rules)]


def inline_suppressions(path: Path) -> dict[int, set[str]]:
    """{строка: набор правил} из комментариев в самом файле.

    Пустой набор означает «подавить любое правило на этой строке».
    Комментарий действует на свою строку и на следующую.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}

    suppressions: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = SUPPRESSION_RE.search(line)
        if match is None:
            continue
        raw = match.group("rules").replace(",", " ").split()
        rules = {token.upper() for token in raw}
        for target in (lineno, lineno + 1):
            if not rules:
                # Сплошное подавление поглощает любой перечень правил...
                suppressions[target] = set()
                continue
            already = suppressions.get(target)
            if already is not None and not already:
                # ...и обратно им не сужается: комментарий '# fstec-lint:
                # ignore' на строке выше глушит строку целиком, даже если
                # на ней самой перечислены отдельные правила.
                continue
            suppressions.setdefault(target, set()).update(rules)
    return suppressions


def _is_suppressed(finding: Finding, suppressions: dict[int, set[str]]) -> bool:
    """Подавлена ли находка комментарием в самом файле.

    Смотрим и на строку нарушающей директивы, и на остальные строки, к
    которым находка относится: комментарий пишут у самой директивы
    ('ports:'), у конкретного элемента внутри неё и на заголовке сервиса
    ('db:' — вывести сервис целиком). Все три формы задокументированы.
    """
    for lineno in (finding.line, *finding.suppress_lines):
        if lineno is None or lineno not in suppressions:
            continue
        rules = suppressions[lineno]
        if not rules or _matches_rule(finding.rule.id, rules):
            return True
    return False


def _is_excluded(name: str, relative: str, patterns: Sequence[str]) -> bool:
    """Исключение задаётся либо именем каталога/файла, либо glob-ом по пути."""
    return _matches_any(name, patterns) or _matches_any(relative, patterns)


def _candidate_files(
    root: Path, exclude: Sequence[str], on_error: Callable[[OSError], None] | None = None
) -> list[Path]:
    if root.is_file():
        return [root]

    # os.walk по умолчанию молча проглатывает ошибки листинга: каталог
    # без прав давал ноль находок, ноль ошибок и код возврата 0. Для
    # инструмента, отчёт которого читают как «проверено всё», это худший
    # из возможных вариантов — теперь такой каталог попадает в errors.
    def _report(error: OSError) -> None:
        if on_error is not None:
            on_error(error)

    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=_report):
        current = Path(dirpath)
        # Обрезаем дерево на месте: в node_modules и .git незачем заходить.
        dirnames[:] = [
            d
            for d in dirnames
            if d not in DEFAULT_EXCLUDED_DIRS
            and not _is_excluded(d, (current / d).relative_to(root).as_posix(), exclude)
        ]
        dirnames.sort()
        for filename in sorted(filenames):
            path = current / filename
            if _is_excluded(filename, path.relative_to(root).as_posix(), exclude):
                continue
            candidates.append(path)
    return candidates


def discover_files(
    root: Path,
    exclude: Sequence[str] = (),
    on_error: Callable[[OSError], None] | None = None,
) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {
        "compose": [],
        "pg_hba": [],
        "postgresql_conf": [],
        "sshd_config": [],
        "systemd_unit": [],
        "dockerfile": [],
    }

    for path in _candidate_files(root, exclude, on_error):
        name = path.name
        if _matches_any(name, COMPOSE_FILE_PATTERNS):
            found["compose"].append(path)
        elif _matches_any(name, PG_HBA_PATTERNS):
            found["pg_hba"].append(path)
        elif _matches_any(name, POSTGRESQL_CONF_PATTERNS):
            found["postgresql_conf"].append(path)
        elif _matches_any(name, SSHD_CONFIG_PATTERNS):
            found["sshd_config"].append(path)
        elif _matches_any(name, SYSTEMD_UNIT_PATTERNS):
            found["systemd_unit"].append(path)
        elif _matches_any(name, DOCKERFILE_PATTERNS):
            found["dockerfile"].append(path)
    return found


def _describe(exc: Exception) -> str:
    return " ".join(f"{type(exc).__name__}: {exc}".split())


def _finding(rule: Rule, path: Path, item: CheckResult) -> Finding:
    """Собирает Finding из 3- или 4-элементного результата проверки."""
    location, detail, line = item[0], item[1], item[2]
    suppress_lines = item[3] if len(item) > 3 else ()
    return Finding(
        rule=rule,
        file=str(path),
        location=location,
        detail=detail,
        line=line,
        suppress_lines=tuple(suppress_lines or ()),
    )


def _run_registry(
    result: ScanResult,
    paths: list[Path],
    rules: list[Rule],
    registry: Mapping[str, CheckFn],
    parse: Callable[[Path], Any],
) -> None:
    for path in paths:
        # Один битый или бинарный файл не должен ронять весь прогон:
        # имя файла с расширением .service ещё не гарантирует, что внутри
        # текстовый юнит systemd.
        try:
            data = parse(path)
        except Exception as exc:  # noqa: BLE001 — сообщаем и идём дальше
            result.errors.append(
                ScanError(file=str(path), message=f"не удалось разобрать: {_describe(exc)}")
            )
            continue

        # Проверки ловятся по одной, а не всем блоком: раньше падение
        # любой из них уничтожало уже найденное по этому файлу другими
        # правилами и записывалось как ошибка разбора — то есть баг
        # инструмента выглядел как проблема проверяемого файла.
        file_findings: list[Finding] = []
        for rule in rules:
            check_fn = registry.get(rule.id)
            if check_fn is None:
                continue
            try:
                file_findings.extend(_finding(rule, path, item) for item in check_fn(data))
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    ScanError(
                        file=str(path),
                        message=f"сбой проверки {rule.id}: {_describe(exc)}",
                    )
                )

        suppressions = inline_suppressions(path)
        kept = [f for f in file_findings if not _is_suppressed(f, suppressions)]
        result.suppressed += len(file_findings) - len(kept)
        result.findings.extend(kept)


def scan(
    root: Path,
    rules_dir: Path = RULES_DIR,
    exclude: Sequence[str] = (),
    select: Sequence[str] = (),
    ignore: Sequence[str] = (),
) -> ScanResult:
    """Сканирует root и возвращает находки (по убыванию severity) и ошибки разбора."""
    rules_by_target: dict[str, list[Rule]] = {}
    for rule in filter_rules(load_rules(rules_dir), select, ignore):
        rules_by_target.setdefault(rule.target, []).append(rule)

    result = ScanResult()

    def _walk_error(error: OSError) -> None:
        target = getattr(error, "filename", None) or str(root)
        result.errors.append(
            ScanError(file=str(target), message=f"не удалось обойти каталог: {_describe(error)}")
        )

    files = discover_files(root, exclude, _walk_error)

    registries: list[tuple[str, Mapping[str, CheckFn], Callable[[Path], Any]]] = [
        ("compose", compose_checks.REGISTRY, parse_compose),
        ("postgresql_conf", postgres_checks.POSTGRESQL_CONF_REGISTRY, parse_postgresql_conf),
        ("pg_hba", postgres_checks.PG_HBA_REGISTRY, parse_pg_hba),
        ("sshd_config", sshd_checks.REGISTRY, parse_sshd_config),
        ("systemd_unit", systemd_checks.REGISTRY, parse_systemd_unit),
        ("dockerfile", dockerfile_checks.REGISTRY, parse_dockerfile),
    ]
    for target, registry, parse in registries:
        target_rules = rules_by_target.get(target, [])
        # Ни одного активного правила для этого типа файлов — разбирать
        # их незачем. Иначе --select/--ignore не спасали от битого файла
        # отключённого типа: он всё равно давал ошибку разбора и код 3.
        if not target_rules:
            continue
        _run_registry(result, files[target], target_rules, registry, parse)

    result.findings.sort(key=lambda f: (-int(f.rule.severity), f.file, f.rule.id, f.location))
    result.errors.sort(key=lambda e: e.file)
    return result
