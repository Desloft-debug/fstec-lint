from __future__ import annotations

import fnmatch
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from .checks import compose_checks, postgres_checks, sshd_checks, systemd_checks
from .models import Finding, Rule, Severity
from .parsers.compose import parse_compose
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

CheckFn = Callable[[Any], list[tuple[str, str]]]


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


def discover_files(root: Path) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {
        "compose": [],
        "pg_hba": [],
        "postgresql_conf": [],
        "sshd_config": [],
        "systemd_unit": [],
    }
    if root.is_file():
        candidates = [root]
    else:
        candidates = [p for p in root.rglob("*") if p.is_file()]

    for path in candidates:
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
    return found


def _run_registry(
    findings: list[Finding],
    paths: list[Path],
    rules: list[Rule],
    registry: Mapping[str, CheckFn],
    parse: Callable[[Path], Any],
) -> None:
    for path in paths:
        data = parse(path)
        for rule in rules:
            check_fn = registry.get(rule.id)
            if check_fn is None:
                continue
            for location, detail in check_fn(data):
                findings.append(
                    Finding(rule=rule, file=str(path), location=location, detail=detail)
                )


def scan(root: Path, rules_dir: Path = RULES_DIR) -> list[Finding]:
    """Сканирует каталог root и возвращает список находок, отсортированных по убыванию severity."""
    rules_by_target: dict[str, list[Rule]] = {}
    for rule in load_rules(rules_dir):
        rules_by_target.setdefault(rule.target, []).append(rule)

    files = discover_files(root)
    findings: list[Finding] = []

    _run_registry(
        findings,
        files["compose"],
        rules_by_target.get("compose", []),
        compose_checks.REGISTRY,
        parse_compose,
    )
    _run_registry(
        findings,
        files["postgresql_conf"],
        rules_by_target.get("postgresql_conf", []),
        postgres_checks.POSTGRESQL_CONF_REGISTRY,
        parse_postgresql_conf,
    )
    _run_registry(
        findings,
        files["pg_hba"],
        rules_by_target.get("pg_hba", []),
        postgres_checks.PG_HBA_REGISTRY,
        parse_pg_hba,
    )
    _run_registry(
        findings,
        files["sshd_config"],
        rules_by_target.get("sshd_config", []),
        sshd_checks.REGISTRY,
        parse_sshd_config,
    )
    _run_registry(
        findings,
        files["systemd_unit"],
        rules_by_target.get("systemd_unit", []),
        systemd_checks.REGISTRY,
        parse_systemd_unit,
    )

    findings.sort(key=lambda f: (-int(f.rule.severity), f.file, f.rule.id))
    return findings
