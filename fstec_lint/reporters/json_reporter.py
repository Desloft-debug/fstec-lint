from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..models import Finding
from ._common import report_data

if TYPE_CHECKING:
    from ..engine import ScanResult


def render(findings: list[Finding] | ScanResult) -> str:
    data = report_data(findings)
    findings = data.findings
    payload = [
        {
            "rule_id": finding.rule.id,
            "title": finding.rule.title,
            "severity": finding.rule.severity.name.lower(),
            "measure": finding.rule.measure,
            "measure_title": finding.rule.measure_title,
            "orders": finding.rule.orders,
            "submeasure": finding.rule.submeasure,
            "submeasure_title": finding.rule.submeasure_title,
            "activity": finding.rule.activity,
            "activity_title": finding.rule.activity_title,
            "pdn_measure": finding.rule.pdn_measure,
            "pdn_measure_title": finding.rule.pdn_measure_title,
            "file": finding.relative_file(),
            "line": finding.line,
            "location": finding.location,
            "detail": finding.detail,
            "remediation": finding.rule.remediation,
        }
        for finding in findings
    ]
    if data.has_context:
        return json.dumps(
            {
                "findings": payload,
                "errors": [{"file": file, "message": message} for file, message in data.errors],
                "partial": bool(data.errors),
                "suppressed": data.suppressed,
                "limitations": data.notes()[-1],
            },
            ensure_ascii=False,
            indent=2,
        )
    return json.dumps(payload, ensure_ascii=False, indent=2)
