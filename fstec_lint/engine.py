from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks import (
    compose_checks,
    dockerfile_checks,
    linux_checks,
    nginx_checks,
    postfix_checks,
    postgres_checks,
    sshd_checks,
    systemd_checks,
)
from .checks.base import CheckResult, CheckResults
from .models import Finding, Rule, Severity
from .parsers.compose import parse_compose
from .parsers.dockerfile import parse_dockerfile
from .parsers.linux import (
    parse_login_defs,
    parse_pwquality,
    parse_rsyslog,
    parse_useradd_defaults,
)
from .parsers.nginx import parse_nginx
from .parsers.postfix import parse_postfix_main
from .parsers.postgres import parse_pg_hba, parse_postgresql_conf
from .parsers.sshd import parse_sshd_config
from .parsers.systemd import parse_systemd_unit
from .pdn import in_base_set

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
LOGIN_DEFS_PATTERNS = ("login.defs",)
PWQUALITY_PATTERNS = ("pwquality.conf",)
RSYSLOG_PATTERNS = ("rsyslog.conf",)
NGINX_PATTERNS = ("nginx.conf",)
# Имена общие, поэтому нужен признак в пути: default/useradd, postfix/main.cf.
USERADD_DEFAULTS = ("default", "useradd")
POSTFIX_MAIN = "main.cf"
# Файлы сайтов nginx, которые проверяются отдельно, если рядом нет nginx.conf.
NGINX_SITE_DIRS = frozenset({"conf.d", "sites-available", "sites-enabled", "http.d"})

# Сторонние и служебные каталоги, которые не сканируются.
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

# Подавление в самом файле; действует на свою и следующую строку:
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
                    submeasure=item.get("submeasure", ""),
                    submeasure_title=item.get("submeasure_title", ""),
                    activity=item.get("activity", ""),
                    activity_title=item.get("activity_title", ""),
                    cwe=item.get("cwe", ""),
                    weakness_type=item.get("weakness_type", ""),
                    pdn_measure=item.get("pdn_measure", ""),
                    pdn_measure_title=item.get("pdn_measure_title", ""),
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


def filter_by_uz(rules: list[Rule], level: int | None) -> list[Rule]:
    """Правила, чья мера входит в базовый набор приказа N 21 для уровня УЗ."""
    if level is None:
        return rules
    return [rule for rule in rules if in_base_set(rule.pdn_measure, level)]


def unknown_patterns(rules: list[Rule], patterns: Sequence[str]) -> list[str]:
    """Шаблоны, не подошедшие ни к одному правилу, — обычно это опечатка."""
    return [p for p in patterns if not any(_matches_rule(rule.id, [p]) for rule in rules)]


def inline_suppressions(path: Path) -> dict[int, set[str]]:
    """{строка: правила} из комментариев в файле. Пустой набор — все правила."""
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
                # Подавление без списка правил перекрывает любой список.
                suppressions[target] = set()
                continue
            already = suppressions.get(target)
            if already is not None and not already:
                # Строка уже подавлена целиком.
                continue
            suppressions.setdefault(target, set()).update(rules)
    return suppressions


def _is_suppressed(finding: Finding, suppressions: dict[int, set[str]]) -> bool:
    """Подавлена ли находка комментарием в самом файле."""
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

    # Без onerror os.walk молча пропускает нечитаемые каталоги.
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
        "login_defs": [],
        "pwquality": [],
        "rsyslog": [],
        "nginx": [],
        "useradd_defaults": [],
        "postfix_main": [],
    }
    nginx_sites: list[Path] = []

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
        elif _matches_any(name, LOGIN_DEFS_PATTERNS):
            found["login_defs"].append(path)
        elif _matches_any(name, PWQUALITY_PATTERNS):
            found["pwquality"].append(path)
        elif _matches_any(name, RSYSLOG_PATTERNS):
            found["rsyslog"].append(path)
        elif _matches_any(name, NGINX_PATTERNS):
            found["nginx"].append(path)
        elif name.endswith(".conf") and _is_nginx_site(path, root):
            nginx_sites.append(path)
        elif (path.parent.name, name) == USERADD_DEFAULTS:
            found["useradd_defaults"].append(path)
        elif name == POSTFIX_MAIN and _has_part(path, root, "postfix"):
            found["postfix_main"].append(path)
    # Файл сайта уже читается через include основного nginx.conf.
    roots = {p.parent for p in found["nginx"]}
    found["nginx"].extend(p for p in nginx_sites if p.parent.parent not in roots)
    return found


def _has_part(path: Path, root: Path, word: str) -> bool:
    """Есть ли word в одном из трёх ближайших каталогов внутри root."""
    try:
        parts = path.parent.relative_to(root).parts
    except ValueError:
        parts = path.parent.parts
    return any(word in part.lower() for part in parts[-3:])


def _is_nginx_site(path: Path, root: Path) -> bool:
    """Файл в conf.d и подобных каталогах, если выше по пути есть «nginx»."""
    return path.parent.name in NGINX_SITE_DIRS and _has_part(path.parent, root, "nginx")


def _describe(exc: Exception) -> str:
    return " ".join(f"{type(exc).__name__}: {exc}".split())


def _finding(rule: Rule, path: Path, item: CheckResult) -> Finding:
    """Собирает Finding из 3- или 4-элементного результата проверки."""
    location, detail, line = item[0], item[1], item[2]
    suppress_lines = item[3] if len(item) > 3 else ()
    # Строка из файла, подключённого через Include, несёт имя этого файла.
    source = getattr(line, "file", None)
    return Finding(
        rule=rule,
        file=source or str(path),
        location=location,
        detail=detail,
        line=int(line) if line is not None else None,
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
        # Битый файл попадает в ошибки, остальные проверяются дальше.
        try:
            data = parse(path)
        except Exception as exc:  # noqa: BLE001 — сообщаем и идём дальше
            result.errors.append(
                ScanError(file=str(path), message=f"не удалось разобрать: {_describe(exc)}")
            )
            continue

        # Сбой одной проверки не отменяет результаты остальных.
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

        # Подавления читаются из того файла, куда указывает находка.
        suppressions: dict[str, dict[int, set[str]]] = {}
        kept = []
        for finding in file_findings:
            if finding.file not in suppressions:
                suppressions[finding.file] = inline_suppressions(Path(finding.file))
            if not _is_suppressed(finding, suppressions[finding.file]):
                kept.append(finding)
        result.suppressed += len(file_findings) - len(kept)
        result.findings.extend(kept)


def scan(
    root: Path,
    rules_dir: Path = RULES_DIR,
    exclude: Sequence[str] = (),
    select: Sequence[str] = (),
    ignore: Sequence[str] = (),
    uz: int | None = None,
) -> ScanResult:
    """Сканирует root и возвращает находки (по убыванию severity) и ошибки разбора."""
    rules_by_target: dict[str, list[Rule]] = {}
    for rule in filter_by_uz(filter_rules(load_rules(rules_dir), select, ignore), uz):
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
        ("login_defs", linux_checks.LOGIN_DEFS_REGISTRY, parse_login_defs),
        ("pwquality", linux_checks.PWQUALITY_REGISTRY, parse_pwquality),
        ("rsyslog", linux_checks.RSYSLOG_REGISTRY, parse_rsyslog),
        ("nginx", nginx_checks.REGISTRY, parse_nginx),
        ("useradd_defaults", linux_checks.USERADD_REGISTRY, parse_useradd_defaults),
        ("postfix_main", postfix_checks.REGISTRY, parse_postfix_main),
    ]
    for target, registry, parse in registries:
        target_rules = rules_by_target.get(target, [])
        # Нет активных правил для этого типа — файлы не разбираем.
        if not target_rules:
            continue
        _run_registry(result, files[target], target_rules, registry, parse)

    result.findings.sort(key=lambda f: (-int(f.rule.severity), f.file, f.rule.id, f.location))
    result.errors.sort(key=lambda e: e.file)
    return result
