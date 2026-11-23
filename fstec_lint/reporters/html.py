from __future__ import annotations

from collections import Counter
from html import escape
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ._common import report_data

if TYPE_CHECKING:
    from ..engine import ScanResult


SEVERITY_COLOR = {
    Severity.CRITICAL: "#b91c1c",
    Severity.HIGH: "#c2410c",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#4b5563",
}


_LABELS = {
    Severity.CRITICAL: "Критические",
    Severity.HIGH: "Высокие",
    Severity.MEDIUM: "Средние",
    Severity.LOW: "Низкие",
}


def _row(finding: Finding, anchor: str) -> str:
    color = SEVERITY_COLOR[finding.rule.severity]
    path = finding.relative_file()
    where = path if finding.line is None else f"{path}:{finding.line}"
    return f"""
        <tr id="{anchor}">
          <td><span class="badge" style="background:{color}">{finding.rule.severity.name}</span></td>
          <td>{escape(finding.rule.id)}</td>
          <td>{escape(finding.rule.title)}</td>
          <td>{escape(finding.rule.measure)}<br><small>{escape(finding.rule.measure_title)}</small><br><small>{escape(finding.rule.orders)}</small></td>
          <td>{escape(where)}<br><small>{escape(finding.location)}</small></td>
          <td>{escape(finding.detail)}</td>
          <td>{escape(finding.rule.remediation)}</td>
        </tr>"""


def render(findings: list[Finding] | ScanResult, title: str = "fstec-lint report") -> str:
    data = report_data(findings)
    findings = data.findings
    notes = "".join(f"<p>{escape(note)}</p>" for note in data.notes())
    counts = Counter(finding.rule.severity for finding in findings)
    file_counts = Counter(finding.relative_file() for finding in findings)
    priority_index: dict[Severity, int] = {}
    file_index: dict[str, int] = {}
    for index, finding in enumerate(findings, 1):
        priority_index.setdefault(finding.rule.severity, index)
        file_index.setdefault(finding.relative_file(), index)

    cards = []
    for severity in sorted(Severity, reverse=True):
        content = f'<span class="num">{counts[severity]}</span>{_LABELS[severity]}'
        style = f'style="--accent:{SEVERITY_COLOR[severity]}"'
        first_priority = priority_index.get(severity)
        cards.append(
            f'<a class="card" {style} href="#row-{first_priority}">{content}</a>'
            if first_priority
            else f'<span class="card" {style}>{content}</span>'
        )
    summary_cards = "".join(cards)
    files = "".join(
        f'<li><a href="#row-{file_index[file]}">{escape(file)}</a> <span class="count">{count}</span></li>'
        for file, count in sorted(file_counts.items())
    )
    file_nav = (
        f'<details class="files"><summary>Файлы с находками ({len(file_counts)})</summary><ul>{files}</ul></details>'
        if files
        else ""
    )
    if data.errors:
        status = f"Неполная проверка: ошибок и пропусков {len(data.errors)}"
        status_class = "partial"
    elif data.has_context and data.files_checked == 0:
        status, status_class = "Поддерживаемые файлы не найдены", "partial"
    elif data.has_context:
        status, status_class = "Без зарегистрированных ошибок", "ready"
    else:
        status, status_class = "Сведения о полноте отсутствуют", "partial"
    scope = f" · Файлов передано на проверку: {data.files_checked}" if data.has_context else ""
    rows = "".join(_row(f, f"row-{i}") for i, f in enumerate(findings, 1)) or (
        '<tr><td colspan="7" class="empty">Нарушений не найдено</td></tr>'
    )

    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{escape(title)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, "Segoe UI", sans-serif; margin: 0; background:#f2f5f8; color:#142537; }}
  main {{ max-width: 1400px; margin:auto; padding:clamp(1rem, 3vw, 2.5rem); }}
  header, .panel {{ background:white; padding:clamp(1rem, 2vw, 1.5rem); border:1px solid #dce6ee; border-radius:14px; }}
  header {{ border-top:5px solid #1b5971; }}
  h1 {{ margin:0 0 .65rem; font-size:clamp(1.35rem,3vw,2rem); overflow-wrap:anywhere; }}
  h2 {{ margin:.2rem 0 .8rem; font-size:1.15rem; }}
  p {{ margin:.4rem 0; }}
  a {{ color:#15556d; }}
  .status {{ display:inline-block; padding:.35rem .65rem; border-radius:6px; font-weight:650; }}
  .partial {{ background:#fff1db; color:#773f00; }}
  .ready {{ background:#e7f2ed; color:#285344; }}
  .subtitle, small, .count {{ color:#496071; }}
  .summary {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(125px,1fr)); gap:.7rem; margin:1rem 0; }}
  .card {{ display:block; text-decoration:none; color:#182d3b; background:white; border:1px solid #dce6ee; border-top:3px solid var(--accent); border-radius:9px; padding:.8rem; }}
  .card:focus-visible, .card:hover {{ outline:2px solid #1b5971; }}
  .num {{ display:block; font-size:1.6rem; font-weight:700; }}
  .panel, details {{ margin-top:.8rem; }}
  summary {{ cursor:pointer; font-weight:650; }}
  .files ul {{ max-height:15rem; overflow:auto; margin:.6rem 0; padding-left:1.4rem; overflow-wrap:anywhere; }}
  .scroll {{ overflow:auto; }}
  table {{ min-width:760px; width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; padding:.55rem; border-bottom:1px solid #dce6ee; vertical-align:top; font-size:.87rem; overflow-wrap:anywhere; }}
  th {{ color:#40586a; background:#eef3f7; font-size:.8rem; }}
  tr:target {{ background:#e4f2f7; }}
  .badge {{ color:white; padding:.13rem .38rem; border-radius:4px; font-size:.7rem; font-weight:700; white-space:nowrap; }}
  .empty {{ text-align:center; color:#496071; padding:1rem; }}
  .notes {{ color:#40586a; }}

</style>
</head>
<body>
<main>
  <header>
    <h1>{escape(title)}</h1>
    <p class="status {status_class}">{status}</p>
    <p class="subtitle">Всего находок: {len(findings)}{scope}</p>
  </header>
  <nav aria-label="Находки по серьёзности" class="summary">{summary_cards}</nav>
  <section class="panel">
    <h2>Находки и рекомендации</h2>
    {file_nav}
    <div class="scroll">
    <table>
    <thead>
      <tr><th>Приоритет</th><th>ID</th><th>Нарушение</th><th>Мера ФСТЭК</th><th>Расположение</th><th>Факт</th><th>Рекомендация</th></tr>
    </thead>
    <tbody>{rows}</tbody>
    </table>
    </div>
  </section>
  <details class="panel notes"{" open" if data.errors else ""}>
    <summary>Полнота и границы проверки</summary>
    {notes}
  </details>
</main>
</body>
</html>
"""
