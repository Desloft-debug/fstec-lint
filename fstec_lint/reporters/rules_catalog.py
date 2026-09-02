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

# "ЗСВ.2 / УПД.4" -> ЗСВ, УПД
_MEASURE_GROUP_RE = re.compile(r"([А-ЯЁ]{2,})")


def measure_groups(rule: Rule) -> list[str]:
    """Коды групп мер, затронутых правилом, без номеров внутри группы."""
    return list(dict.fromkeys(_MEASURE_GROUP_RE.findall(rule.measure)))


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
    lines.append(f"Затронутые группы мер ФСТЭК: {summary}")
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
                "orders": rule.orders,
                "description": rule.description,
                "remediation": rule.remediation,
            }
            for rule in sorted(rules, key=lambda r: r.id)
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
