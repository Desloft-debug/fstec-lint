from __future__ import annotations

import hashlib
import json

from .. import __version__
from ..models import Finding, Severity

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _fingerprint(finding: Finding) -> str:
    return hashlib.sha256(finding.fingerprint().encode("utf-8")).hexdigest()[:16]


def render(findings: list[Finding]) -> str:
    rules: dict[str, dict] = {}
    results = []

    for finding in findings:
        rule = finding.rule
        if rule.id not in rules:
            rules[rule.id] = {
                "id": rule.id,
                "name": rule.id,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation},
                "defaultConfiguration": {"level": LEVEL[rule.severity]},
                "properties": {"tags": ["security", "fstec", rule.measure]},
            }
        results.append(
            {
                "ruleId": rule.id,
                "level": LEVEL[rule.severity],
                "message": {
                    "text": f"{finding.detail} — мера {rule.measure} ({rule.measure_title})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.relative_file()},
                            # Строка известна не для всех форматов: у сервиса в
                            # compose она есть, у «во всём файле нет HEALTHCHECK» —
                            # условная. SARIF требует положительный номер строки.
                            "region": {"startLine": finding.line or 1},
                        }
                    }
                ],
                # Отпечаток не зависит от номера строки, поэтому GitHub Code
                # Scanning не заводит новый алерт после сдвига файла.
                "partialFingerprints": {"fstecLintFingerprint/v1": _fingerprint(finding)},
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fstec-lint",
                        "version": __version__,
                        "informationUri": "https://github.com/Desloft-debug/fstec-lint",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
