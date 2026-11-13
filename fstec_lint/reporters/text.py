from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._common import report_data

if TYPE_CHECKING:
    from ..engine import ScanResult


SEVERITY_ICON = {
    Severity.CRITICAL: "[CRIT]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED] ",
    Severity.LOW: "[LOW] ",
}


def render(findings: list[Finding] | ScanResult) -> str:
    data = report_data(findings)
    findings = data.findings
    if not findings:
        return "\n".join(["fstec-lint: нарушений не найдено.", *data.notes()])

    lines: list[str] = []
    counts = {s: 0 for s in Severity}
    for finding in findings:
        counts[finding.rule.severity] += 1
        icon = SEVERITY_ICON[finding.rule.severity]
        lines.append(f"{icon} {finding.rule.id} {finding.rule.title}")
        path = finding.relative_file()
        location = path if finding.line is None else f"{path}:{finding.line}"
        lines.append(f"       файл: {location}")
        lines.append(f"       где:  {finding.location}")
        lines.append(f"       мера: {finding.rule.measure} — {finding.rule.measure_title}")
        if finding.rule.submeasure:
            lines.append(
                f"       подмера: {finding.rule.submeasure} — {finding.rule.submeasure_title}"
            )
        if finding.rule.pdn_measure:
            lines.append(
                f"       ПДн:  {finding.rule.pdn_measure} — {finding.rule.pdn_measure_title}"
            )
        if finding.rule.activity:
            lines.append(f"       процесс: {finding.rule.activity} — {finding.rule.activity_title}")
        if finding.rule.orders:
            lines.append(f"       приказ: {finding.rule.orders}")
        lines.append(f"       факт: {finding.detail}")
        lines.append(f"       фикс: {finding.rule.remediation}")
        lines.append("")

    summary = ", ".join(
        f"{severity.name.lower()}={counts[severity]}"
        for severity in sorted(Severity, reverse=True)
        if counts[severity]
    )
    lines.append(f"Итого находок: {len(findings)} ({summary})")
    return "\n".join([*lines, "", *data.notes()])
