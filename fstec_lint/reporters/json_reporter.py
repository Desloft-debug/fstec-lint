from __future__ import annotations

import json

from ..models import Finding


def render(findings: list[Finding]) -> str:
    payload = [
        {
            "rule_id": finding.rule.id,
            "title": finding.rule.title,
            "severity": finding.rule.severity.name.lower(),
            "measure": finding.rule.measure,
            "measure_title": finding.rule.measure_title,
            "orders": finding.rule.orders,
            "file": finding.relative_file(),
            "line": finding.line,
            "location": finding.location,
            "detail": finding.detail,
            "remediation": finding.rule.remediation,
        }
        for finding in findings
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)
