from __future__ import annotations

import json
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..models import Finding, Rule
from ._common import ERROR_MESSAGE, relative_file, report_data
from ._regulatory import reference_context

if TYPE_CHECKING:
    from ..engine import ScanResult


def render(
    findings: list[Finding] | ScanResult,
    *,
    active_rules: Sequence[Rule] = (),
) -> str:
    result = findings if not isinstance(findings, list) else None
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
    if result is not None:
        return json.dumps(
            {
                "findings": payload,
                "errors": [
                    {
                        "file": relative_file(error.file),
                        "message": ERROR_MESSAGE,
                        "reason": error.code,
                        **({"rule_id": error.rule_id} if error.rule_id is not None else {}),
                        **({"subjects": list(error.subjects)} if error.subjects else {}),
                    }
                    for error in result.errors
                ],
                "partial": bool(data.errors),
                "files_checked": data.files_checked,
                "suppressed": data.suppressed,
                "coverage": {
                    "unit": "rule_and_input_file",
                    "includes_suppressed_findings": True,
                    "rules": {
                        rule_id: {
                            "indicator_not_observed": counts["pass"],
                            "indicator_observed": counts["fail"],
                            "indeterminate": counts["unavailable"],
                        }
                        for rule_id, counts in sorted((result.coverage or {}).items())
                    },
                },
                "declared_gis_class": result.declared_gis_class,
                "regulatory": {
                    rule.id: reference_context(rule, result.declared_gis_class)
                    for rule in active_rules
                },
                "limitations": data.notes()[-1],
            },
            ensure_ascii=False,
            indent=2,
        )
    return json.dumps(payload, ensure_ascii=False, indent=2)
