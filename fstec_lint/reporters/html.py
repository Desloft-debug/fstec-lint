from __future__ import annotations

from html import escape

from ..models import Finding, Severity

SEVERITY_COLOR = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#4b5563",
}


def _row(finding: Finding) -> str:
    color = SEVERITY_COLOR[finding.rule.severity]
    return f"""
        <tr>
          <td><span class="badge" style="background:{color}">{finding.rule.severity.name}</span></td>
          <td>{escape(finding.rule.id)}</td>
          <td>{escape(finding.rule.title)}</td>
          <td>{escape(finding.rule.measure)}<br><small>{escape(finding.rule.measure_title)}</small><br><small>{escape(finding.rule.orders)}</small></td>
          <td>{escape(finding.file)}<br><small>{escape(finding.location)}</small></td>
          <td>{escape(finding.detail)}</td>
          <td>{escape(finding.rule.remediation)}</td>
        </tr>"""


def render(findings: list[Finding], title: str = "fstec-lint report") -> str:
    counts = {s: 0 for s in Severity}
    for finding in findings:
        counts[finding.rule.severity] += 1

    summary_cards = "".join(
        f'<div class="card" style="border-color:{SEVERITY_COLOR[s]}">'
        f'<div class="num">{counts[s]}</div><div class="label">{s.name}</div></div>'
        for s in sorted(Severity, reverse=True)
    )

    rows = "".join(_row(f) for f in findings) or (
        '<tr><td colspan="7" class="empty">Нарушений не найдено</td></tr>'
    )

    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>{escape(title)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 2rem; background:#0b0f14; color:#e5e7eb; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.2rem; }}
  .subtitle {{ color: #9ca3af; margin-top: 0; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; }}
  th, td {{ text-align: left; padding: 0.6rem; border-bottom: 1px solid #1f2937; vertical-align: top; font-size: 0.9rem; }}
  th {{ color: #9ca3af; text-transform: uppercase; font-size: 0.75rem; }}
  .badge {{ color: white; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }}
  .summary {{ display: flex; gap: 1rem; margin-top: 1rem; flex-wrap: wrap; }}
  .card {{ border: 1px solid; border-radius: 8px; padding: 0.8rem 1.2rem; text-align: center; min-width: 90px; }}
  .num {{ font-size: 1.6rem; font-weight: 700; }}
  .label {{ font-size: 0.75rem; color: #9ca3af; }}
  .empty {{ text-align: center; color: #9ca3af; padding: 1.5rem; }}
  small {{ color: #9ca3af; }}
</style>
</head>
<body>
  <h1>{escape(title)}</h1>
  <p class="subtitle">Всего находок: {len(findings)}</p>
  <div class="summary">{summary_cards}</div>
  <table>
    <thead>
      <tr><th>Severity</th><th>ID</th><th>Нарушение</th><th>Мера ФСТЭК</th><th>Расположение</th><th>Факт</th><th>Рекомендация</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
