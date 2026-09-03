from __future__ import annotations

import fnmatch
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks import compose_checks, dockerfile_checks, postgres_checks, sshd_checks, systemd_checks
from .checks.base import CheckResult
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

CheckFn = Callable[[Any], list[CheckResult]]


@dataclass(frozen=True)
class ScanError:
    """Файл, который не удалось разобрать: битый синтаксис, не UTF-8, нет прав."""

    file: str
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)


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
                )
            )
    return rules


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _is_excluded(name: str, relative: str, patterns: Sequence[str]) -> bool:
    """Исключение задаётся либо именем каталога/файла, либо glob-ом по пути."""
    return _matches_any(name, patterns) or _matches_any(relative, patterns)


def _candidate_files(root: Path, exclude: Sequence[str]) -> list[Path]:
    if root.is_file():
        return [root]

    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
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


def discover_files(root: Path, exclude: Sequence[str] = ()) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {
        "compose": [],
        "pg_hba": [],
        "postgresql_conf": [],
        "sshd_config": [],
        "systemd_unit": [],
        "dockerfile": [],
    }

    for path in _candidate_files(root, exclude):
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
            file_findings = [
                Finding(rule=rule, file=str(path), location=location, detail=detail, line=line)
                for rule in rules
                if (check_fn := registry.get(rule.id)) is not None
                for location, detail, line in check_fn(data)
            ]
        except Exception as exc:  # noqa: BLE001 — сообщаем и идём дальше
            result.errors.append(
                ScanError(file=str(path), message=" ".join(f"{type(exc).__name__}: {exc}".split()))
            )
            continue
        result.findings.extend(file_findings)


def scan(root: Path, rules_dir: Path = RULES_DIR, exclude: Sequence[str] = ()) -> ScanResult:
    """Сканирует root и возвращает находки (по убыванию severity) и ошибки разбора."""
    rules_by_target: dict[str, list[Rule]] = {}
    for rule in load_rules(rules_dir):
        rules_by_target.setdefault(rule.target, []).append(rule)

    files = discover_files(root, exclude)
    result = ScanResult()

    registries: list[tuple[str, Mapping[str, CheckFn], Callable[[Path], Any]]] = [
        ("compose", compose_checks.REGISTRY, parse_compose),
        ("postgresql_conf", postgres_checks.POSTGRESQL_CONF_REGISTRY, parse_postgresql_conf),
        ("pg_hba", postgres_checks.PG_HBA_REGISTRY, parse_pg_hba),
        ("sshd_config", sshd_checks.REGISTRY, parse_sshd_config),
        ("systemd_unit", systemd_checks.REGISTRY, parse_systemd_unit),
        ("dockerfile", dockerfile_checks.REGISTRY, parse_dockerfile),
    ]
    for target, registry, parse in registries:
        _run_registry(result, files[target], rules_by_target.get(target, []), registry, parse)

    result.findings.sort(key=lambda f: (-int(f.rule.severity), f.file, f.rule.id, f.location))
    result.errors.sort(key=lambda e: e.file)
    return result
