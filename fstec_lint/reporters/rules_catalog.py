"""Вывод каталога правил: что вообще умеет проверять инструмент и какие
группы мер ФСТЭК он затрагивает. Полезно, когда перечень проверок нужно
приложить к документам по оценке соответствия."""

from __future__ import annotations

import json
import re
from collections import Counter

from ..models import Rule, Severity

TARGET_LABELS = {
    "compose": "docker-compose.yml / compose.yaml",
    "dockerfile": "Dockerfile",
    "postgresql_conf": "postgresql.conf",
    "pg_hba": "pg_hba.conf",
    "sshd_config": "sshd_config",
    "systemd_unit": "*.service (systemd)",
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
}

# "п. 63 д)" -> ("п. 63", "д"); "п. 34 б)" -> ("п. 34", "б")
_CLAUSE_RE = re.compile(r"п\.\s*(\d+)\s*([а-яё])\)")

# Пункты приказа ФСТЭК N 117, на которые ссылаются правила.
CLAUSE_LABELS = {
    "63": "п. 63 — базовые меры защиты",
    "34": "п. 34 — мероприятия по защите информации",
}


def measure_groups(rule: Rule) -> list[str]:
    """Пункты приказа N 117, затронутые правилом.

    Раньше здесь вырезались коды групп вида ЗСВ/УПД из приказа N 17. В
    приказе N 117 таких кодов нет, поэтому покрытие считается по его
    пунктам — так его можно проверить по тексту приказа, а не по памяти.
    """
    return [f"п. {number} {letter})" for number, letter in _CLAUSE_RE.findall(rule.measure)] or [
        rule.measure
    ]


def _coverage(rules: list[Rule]) -> Counter:
    counter: Counter = Counter()
    for rule in rules:
        for group in measure_groups(rule):
            counter[group] += 1
    return counter


def render_text(rules: list[Rule]) -> str:
    lines = [f"Правил всего: {len(rules)}", ""]

    by_target: dict[str, list[Rule]] = {}
    for rule in rules:
        by_target.setdefault(rule.target, []).append(rule)

    for target, target_rules in by_target.items():
        label = TARGET_LABELS.get(target, target)
        lines.append(f"{label} ({len(target_rules)}):")
        for rule in sorted(target_rules, key=lambda r: r.id):
            severity = SEVERITY_LABEL[rule.severity]
            lines.append(f"  [{severity}] {rule.id}  {rule.measure:<22} {rule.title}")
        lines.append("")

    coverage = _coverage(rules)
    summary = ", ".join(f"{group} ({count})" for group, count in sorted(coverage.items()))
    lines.append(f"Затронутые пункты приказа ФСТЭК N 117: {summary}")
    return "\n".join(lines)


def render_json(rules: list[Rule]) -> str:
    payload = {
        "total": len(rules),
        "measure_groups": dict(sorted(_coverage(rules).items())),
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity.name.lower(),
                "target": rule.target,
                "measure": rule.measure,
                "measure_title": rule.measure_title,
                "measure_groups": measure_groups(rule),
                "methodology": rule.methodology,
                "methodology_title": rule.methodology_title,
                "legacy_measure": rule.legacy_measure,
                "orders": rule.orders,
                "description": rule.description,
                "remediation": rule.remediation,
            }
            for rule in sorted(rules, key=lambda r: r.id)
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
