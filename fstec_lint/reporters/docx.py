"""Binary OOXML report built from safe findings, with no runtime dependency.

Layout follows the historical project style; no standards compliance is claimed.
"""

from __future__ import annotations

import io
import zipfile
from collections import Counter
from datetime import date
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape as _escape

from .. import __version__
from ..models import Finding, Severity
from . import passport
from ._common import ReportData, report_data

if TYPE_CHECKING:
    from ..engine import ScanResult

SEVERITY_NAME = {
    Severity.CRITICAL: "Критический",
    Severity.HIGH: "Высокий",
    Severity.MEDIUM: "Средний",
    Severity.LOW: "Низкий",
}

MONTHS = (
    "января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря",
)  # fmt: skip

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

# Ширины столбцов в twips; сумма — ширина текста A4 при полях 30 и 15 мм (9355).


def escape(text: str) -> str:
    # XML 1.0 excludes controls and surrogate code points, even after escaping.
    return _escape(
        "".join(
            c
            if c in "\t\n\r"
            or 0x20 <= ord(c) <= 0xD7FF
            or 0xE000 <= ord(c) <= 0xFFFD
            or 0x10000 <= ord(c) <= 0x10FFFF
            else "\ufffd"
            for c in text
        )
    )


def _run(text: str, bold: bool = False, size: int | None = None) -> str:
    props = ""
    if bold:
        props += "<w:b/>"
    if size:
        props += f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>'
    rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'


def _p(
    text: str = "",
    style: str | None = None,
    align: str | None = None,
    bold: bool = False,
    size: int | None = None,
    page_break: bool = False,
    runs: str | None = None,
) -> str:
    ppr = ""
    if style:
        ppr += f'<w:pStyle w:val="{style}"/>'
    if page_break:
        ppr += "<w:pageBreakBefore/>"
    if align:
        ppr += f'<w:jc w:val="{align}"/>'
    body = runs if runs is not None else (_run(text, bold, size) if text else "")
    return f"<w:p><w:pPr>{ppr}</w:pPr>{body}</w:p>"


def _heading(text: str, page_break: bool = False) -> str:
    # Preserve the historical distinction between numbered and appendix headings.
    style = "Section" if text[:1].isdigit() else "Heading1"
    return _p(text, style=style, page_break=page_break)


def _caption(text: str) -> str:
    return _p(text, style="Caption")


def _table(rows: list[list[str]], widths: list[int], header: bool = True) -> str:
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    out = [
        "<w:tbl><w:tblPr>"
        f'<w:tblW w:w="{sum(widths)}" w:type="dxa"/>'
        '<w:tblLayout w:type="fixed"/>'
        "<w:tblBorders>"
        + "".join(
            f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
            for side in ("top", "left", "bottom", "right", "insideH", "insideV")
        )
        + "</w:tblBorders>"
        '<w:tblCellMar><w:left w:w="85" w:type="dxa"/>'
        '<w:right w:w="85" w:type="dxa"/></w:tblCellMar>'
        f"</w:tblPr><w:tblGrid>{grid}</w:tblGrid>"
    ]
    for index, row in enumerate(rows):
        is_header = header and index == 0
        trpr = (
            "<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>"
            if is_header
            else "<w:trPr><w:cantSplit/></w:trPr>"
        )
        cells = "".join(
            f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/></w:tcPr>'
            + _p(value, style="TableText", bold=is_header, align="center" if is_header else None)
            + "</w:tc>"
            for value, width in zip(row, widths, strict=True)
        )
        out.append(f"<w:tr>{trpr}{cells}</w:tr>")
    out.append("</w:tbl>")
    # После таблицы нужен абзац, иначе Word склеит соседние таблицы.
    return "".join(out) + _p(style="TableText")


def _toc(headings: list[str]) -> str:
    """Поле оглавления. Word пересчитывает его при открытии (updateFields)."""
    begin = (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r></w:p>'
    )
    placeholder = "".join(_p(h, style="TOC1") for h in headings)
    end = '<w:p><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    return begin + placeholder + end


def _date_ru(day: date) -> str:
    return f"«{day.day:02d}» {MONTHS[day.month - 1]} {day.year} г."


def _title_page(object_name: str, today: date) -> str:
    return "".join(
        [
            _p("Результаты статического анализа конфигураций", style="Title"),
            _p(f"Объект контроля: {object_name}", align="center"),
            _p(f"fstec-lint {__version__}", align="center"),
            _p(_date_ru(today), align="center"),
        ]
    )


def _by_severity(findings: list[Finding]) -> list[list[str]]:
    counts = Counter(f.rule.severity for f in findings)
    rows = [["Степень опасности", "Количество"]]
    for level in sorted(Severity, reverse=True):
        rows.append([SEVERITY_NAME[level], str(counts.get(level, 0))])
    rows.append(["Всего", str(len(findings))])
    return rows


def _by_measure(findings: list[Finding]) -> list[list[str]]:
    counts: Counter[tuple[str, str]] = Counter(
        (f.rule.measure, f.rule.measure_title) for f in findings
    )
    rows = [["Мера из каталога правил", "Наименование меры", "Кол-во"]]
    for (measure, title), count in sorted(counts.items()):
        rows.append([measure, title, str(count)])
    return rows


def _findings_table(findings: list[Finding], today: date) -> list[list[str]]:
    rows = [["№", "Идентификатор", "Уязвимость", "Опасность", "Место", "Мера"]]
    for index, f in enumerate(findings, start=1):
        where = f.relative_file() if f.line is None else f"{f.relative_file()}:{f.line}"
        rows.append(
            [
                str(index),
                passport.identifier(index, today),
                f"{f.rule.id}. {f.rule.title}",
                SEVERITY_NAME[f.rule.severity],
                where,
                f.rule.measure,
            ]
        )
    return rows


def _remediation_table(findings: list[Finding]) -> list[list[str]]:
    rules = {}
    counts: Counter[str] = Counter()
    for f in findings:
        rules[f.rule.id] = f.rule
        counts[f.rule.id] += 1
    ordered = sorted(rules.values(), key=lambda r: (-r.severity, r.id))
    rows = [["Правило", "Уязвимость", "Кол-во", "Рекомендация"]]
    for rule in ordered:
        rows.append([rule.id, rule.title, str(counts[rule.id]), rule.remediation])
    return rows


def _body(data: ReportData, object_name: str, rules_applied: int, today: date) -> str:
    findings = data.findings
    headings = ["1 Область анализа", "2 Результаты анализа"]
    if findings:
        headings += ["3 Рекомендации", "ПРИЛОЖЕНИЕ А Паспорта находок"]
    out = [_title_page(object_name, today)]
    out.append(_p("СОДЕРЖАНИЕ", style="TitleCenter", page_break=True))
    out.append(_toc(headings))
    out.append(_heading(headings[0], page_break=True))
    out.append(_p(f"Объект: {object_name}. Применено правил: {rules_applied}."))
    out.extend(_p(note) for note in data.notes())
    out.append(
        _p(
            "Версия проверяемого ПО, аппаратная платформа и состояние работающих служб "
            "статическим анализом не устанавливаются. Дата отчёта не удостоверяет "
            "дату возникновения недостатка."
        )
    )
    out.append(_heading(headings[1]))
    if not findings:
        out.append(_p("В переданных результатах находок нет; паспорта не составлялись."))
    else:
        out.append(_p(f"Находок в переданных результатах: {len(findings)}."))
        out.append(_caption("Таблица 1 — Находки по степени опасности"))
        out.append(_table(_by_severity(findings), [6000, 3355]))
        out.append(_caption("Таблица 2 — Находки по мерам из каталога правил"))
        out.append(_table(_by_measure(findings), [1900, 6055, 1400]))
        out.append(_caption("Таблица 3 — Перечень находок"))
        out.append(_table(_findings_table(findings, today), [450, 1950, 2350, 1600, 2005, 1000]))
        out.append(_heading("3 Рекомендации", page_break=True))
        out.append(_caption("Таблица 4 — Рекомендации по правилам"))
        out.append(_table(_remediation_table(findings), [1000, 2500, 855, 5000]))
        out.append(_p("ПРИЛОЖЕНИЕ А", style="Heading1", page_break=True))
        out.append(_p("Паспорта находок", style="TitleCenter"))
        out.append(
            _p(
                "Структурированные описания результатов анализа. Наличие полей "
                "паспорта не подтверждает соответствие стандарту или применимость "
                "нормативной привязки правила."
            )
        )
        for index, finding in enumerate(findings, start=1):
            rows = [[name, value] for name, value in passport.passport_rows(finding, index, today)]
            out.append(_caption(f"Таблица А.{index} — Паспорт {passport.identifier(index, today)}"))
            out.append(_table(rows, [3400, 5955], header=False))
    return "".join(out)


def _document(body: str) -> str:
    sect = (
        "<w:sectPr>"
        '<w:footerReference w:type="default" r:id="rIdFooter"/>'
        '<w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="850" w:bottom="1134" w:left="1701" '
        'w:header="709" w:footer="567" w:gutter="0"/>'
        "<w:titlePg/>"
        "</w:sectPr>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:body>{body}{sect}</w:body></w:document>'
    )


STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:styles '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
    '<w:docDefaults>\n<w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" '
    'w:hAnsi="Times New Roman" w:cs="Times New Roman" w:eastAsia="Times New Roman"/>'
    '<w:sz w:val="28"/><w:szCs w:val="28"/><w:lang w:val="ru-RU"/></w:rPr>'
    '</w:rPrDefault>\n<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="360" '
    'w:lineRule="auto"/></w:pPr></w:pPrDefault>\n</w:docDefaults>\n<w:style '
    'w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/>'
    '<w:pPr><w:ind w:firstLine="709"/><w:jc w:val="both"/></w:pPr></w:style>\n<w:style '
    'w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn '
    'w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing '
    'w:after="240"/><w:ind w:firstLine="0"/><w:jc w:val="center"/><w:outlineLvl '
    'w:val="0"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>\n<w:style w:type="paragraph" '
    'w:styleId="Section"><w:name w:val="Section"/><w:basedOn w:val="Normal"/><w:next '
    'w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:after="240"/><w:jc w:val="left"/>'
    '<w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>\n<w:style '
    'w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn '
    'w:val="TitleCenter"/></w:style>\n<w:style w:type="paragraph" '
    'w:styleId="TitleCenter"><w:name w:val="Title Center"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:keepNext/><w:spacing w:after="240"/><w:ind w:firstLine="0"/><w:jc '
    'w:val="center"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>\n<w:style '
    'w:type="paragraph" w:styleId="Caption"><w:name w:val="caption"/><w:basedOn '
    'w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240"/><w:ind '
    'w:firstLine="0"/><w:jc w:val="left"/></w:pPr></w:style>\n<w:style '
    'w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn '
    'w:val="Normal"/><w:pPr><w:spacing w:line="240" w:lineRule="auto"/><w:ind '
    'w:firstLine="0"/><w:jc w:val="left"/></w:pPr><w:rPr><w:sz w:val="24"/><w:szCs '
    'w:val="24"/></w:rPr></w:style>\n<w:style w:type="paragraph" w:styleId="TOC1">'
    '<w:name w:val="toc 1"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:firstLine="0"/>'
    '<w:jc w:val="left"/></w:pPr></w:style>\n<w:style w:type="paragraph" '
    'w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:pPr>'
    '<w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr></w:style>\n</w:styles>'
)

FOOTER = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:ftr '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p>'
    '<w:pPr><w:pStyle w:val="Footer"/></w:pPr><w:r><w:fldChar w:fldCharType="begin"/>'
    '</w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r>'
    '<w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>2</w:t></w:r><w:r><w:fldChar '
    'w:fldCharType="end"/></w:r></w:p></w:ftr>'
)

SETTINGS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:settings '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:updateFields w:val="true"/><w:defaultTabStop w:val="709"/></w:settings>'
)

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types '
    'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n<Default '
    'Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n<Default '
    'Extension="xml" ContentType="application/xml"/>\n<Override '
    'PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.docume'
    'nt.main+xml"/>\n<Override PartName="/word/styles.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles'
    '+xml"/>\n<Override PartName="/word/settings.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settin'
    'gs+xml"/>\n<Override PartName="/word/footer1.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer'
    '+xml"/>\n<Override PartName="/docProps/core.xml" '
    'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>\n'
    "</Types>"
)

ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships '
    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDo'
    'cument" Target="word/document.xml"/>\n<Relationship Id="rId2" '
    'Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-p'
    'roperties" Target="docProps/core.xml"/>\n</Relationships>'
)

DOCUMENT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships '
    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
    '<Relationship Id="rIdStyles" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
    'Target="styles.xml"/>\n<Relationship Id="rIdSettings" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings'
    '" Target="settings.xml"/>\n<Relationship Id="rIdFooter" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" '
    'Target="footer1.xml"/>\n</Relationships>'
)


def _core(object_name: str, today: date) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        "<cp:coreProperties "
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        "<dc:title>"
        + escape("Отчёт о результатах контроля конфигураций: " + object_name)
        + "</dc:title>"
        f"<dc:creator>fstec-lint {__version__}</dc:creator>"
        '<dcterms:created xsi:type="dcterms:W3CDTF">'
        f"{today.isoformat()}T00:00:00Z</dcterms:created>"
        "</cp:coreProperties>"
    )


def _write_part(archive: zipfile.ZipFile, name: str, xml: str) -> None:
    part = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    part.compress_type = zipfile.ZIP_DEFLATED
    part.create_system = 0
    archive.writestr(part, xml.encode("utf-8"))


def render(
    findings: list[Finding] | ScanResult,
    object_name: str,
    rules_applied: int,
    today: date | None = None,
) -> bytes:
    data = report_data(findings)
    today = today or date.today()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        _write_part(archive, "[Content_Types].xml", CONTENT_TYPES)
        _write_part(archive, "_rels/.rels", ROOT_RELS)
        _write_part(archive, "docProps/core.xml", _core(object_name, today))
        _write_part(archive, "word/_rels/document.xml.rels", DOCUMENT_RELS)
        _write_part(archive, "word/styles.xml", STYLES)
        _write_part(archive, "word/settings.xml", SETTINGS)
        _write_part(archive, "word/footer1.xml", FOOTER)
        _write_part(
            archive,
            "word/document.xml",
            _document(_body(data, object_name, rules_applied, today)),
        )
    return buffer.getvalue()
