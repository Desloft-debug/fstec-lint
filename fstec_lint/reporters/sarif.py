from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from .. import __version__
from ..models import Finding, Severity
from ._common import report_data

if TYPE_CHECKING:
    from ..engine import ScanResult


LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _fingerprint(finding: Finding) -> str:
    return hashlib.sha256(finding.fingerprint().encode("utf-8")).hexdigest()[:16]


def _uri(file: str) -> str:
    """Encode a filesystem path as a URI, including Windows drive/UNC paths."""
    windows = PureWindowsPath(file)
    if windows.is_absolute():
        return windows.as_uri()
    if file.startswith("/"):
        return PurePosixPath(file).as_uri()
    return quote(file.replace("\\", "/"), safe="/")


def render(findings: list[Finding] | ScanResult) -> str:
    data = report_data(findings)
    findings = data.findings
    rules: dict[str, dict] = {}
    indices: dict[str, int] = {}
    results = []

    for finding in findings:
        rule = finding.rule
        if rule.id not in rules:
            indices[rule.id] = len(rules)
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
                "ruleIndex": indices[rule.id],
                "level": LEVEL[rule.severity],
                "message": {
                    "text": f"{finding.detail} — мера {rule.measure} ({rule.measure_title})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(finding.relative_file())},
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

    sarif: dict[str, Any] = {
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
    run = sarif["runs"][0]
    run["properties"] = {"limitations": data.notes()[-1]}
    if data.has_context:
        run["properties"]["inlineSuppressed"] = data.suppressed
        run["invocations"] = [
            {
                "executionSuccessful": not data.errors,
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": message},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": _uri(file)}}}
                        ],
                    }
                    for file, message in data.errors
                ],
            }
        ]
    return json.dumps(sarif, ensure_ascii=False, indent=2)
