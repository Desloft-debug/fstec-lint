from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterable

import yaml

from .checks import compose_checks, postgres_checks
from .models import Finding, Rule, Severity
from .parsers.compose import parse_compose
from .parsers.postgres import parse_pg_hba, parse_postgresql_conf

RULES_DIR = Path(__file__).parent / "rules"

COMPOSE_FILE_PATTERNS = ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml")
POSTGRESQL_CONF_PATTERNS = ("postgresql.conf",)
PG_HBA_PATTERNS = ("pg_hba.conf",)

CHECK_REGISTRIES = {
    "compose": compose_checks.REGISTRY,
    "pg_hba": postgres_checks.REGISTRY,
    "postgresql_conf": postgres_checks.REGISTRY,
}


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
                )
            )
    return rules


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def discover_files(root: Path) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {"compose": [], "pg_hba": [], "postgresql_conf": []}
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
    return found


def scan(root: Path, rules_dir: Path = RULES_DIR) -> list[Finding]:
    """Сканирует каталог root и возвращает список находок, отсортированных по убыванию severity."""
    rules_by_target: dict[str, list[Rule]] = {}
    for rule in load_rules(rules_dir):
        rules_by_target.setdefault(rule.target, []).append(rule)

    files = discover_files(root)
    findings: list[Finding] = []

    for path in files["compose"]:
        data = parse_compose(path)
        for rule in rules_by_target.get("compose", []):
            check_fn = CHECK_REGISTRIES["compose"].get(rule.id)
            if check_fn is None:
                continue
            for location, detail in check_fn(data):
                findings.append(Finding(rule=rule, file=str(path), location=location, detail=detail))

    for path in files["postgresql_conf"]:
        settings = parse_postgresql_conf(path)
        for rule in rules_by_target.get("postgresql_conf", []):
            check_fn = CHECK_REGISTRIES["postgresql_conf"].get(rule.id)
            if check_fn is None:
                continue
            for location, detail in check_fn(settings):
                findings.append(Finding(rule=rule, file=str(path), location=location, detail=detail))

    for path in files["pg_hba"]:
        records = parse_pg_hba(path)
        for rule in rules_by_target.get("pg_hba", []):
            check_fn = CHECK_REGISTRIES["pg_hba"].get(rule.id)
            if check_fn is None:
                continue
            for location, detail in check_fn(records):
                findings.append(Finding(rule=rule, file=str(path), location=location, detail=detail))

    findings.sort(key=lambda f: (-int(f.rule.severity), f.file, f.rule.id))
    return findings
