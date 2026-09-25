"""Отчёт о результатах контроля конфигураций в формате DOCX.

Оформление по ГОСТ 7.32-2017: поля 30/15/20/20 мм, Times New Roman,
полуторный интервал, абзацный отступ 1,25 см, номер страницы внизу по
центру, титульный лист без номера. Паспорта уязвимостей идут
приложением А в форме ГОСТ Р 56545-2015.
Документ собирается из OOXML напрямую, без python-docx.
"""

from __future__ import annotations

import io
import zipfile
from collections import Counter
from datetime import date
from xml.sax.saxutils import escape

from .. import __version__
from ..models import Finding, Severity
from . import passport

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
    # Структурные элементы (ВВЕДЕНИЕ, ЗАКЛЮЧЕНИЕ) — по центру, разделы с
    # номером — с абзацного отступа (ГОСТ 7.32-2017, 6.2).
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
        '<w:tblCellMar><w:left w:w="85" w:type="dxa"/><w:right w:w="85" w:type="dxa"/></w:tblCellMar>'
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
    parts = [
        _p("Наименование организации-исполнителя", align="center"),
        _p("_______________________________________", align="center"),
        _p(),
        _p("УТВЕРЖДАЮ", align="right"),
        _p("Руководитель организации", align="right"),
        _p("____________ / ______________", align="right"),
        _p(_date_ru(today), align="right"),
        _p(),
        _p(),
        _p("ОТЧЁТ", align="center", bold=True, size=32),
        _p("о результатах контроля конфигураций", align="center", bold=True),
        _p("информационной системы", align="center", bold=True),
        _p(),
        _p(f"Объект контроля: {object_name}", align="center"),
        _p(f"Средство контроля: fstec-lint {__version__}", align="center"),
        _p(),
        _p(),
        _p("Исполнитель ____________ / ______________", align="right"),
        _p(),
        _p(),
        _p(f"{today.year}", align="center"),
    ]
    return "".join(parts)


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
    rows = [["Пункт приказа № 117", "Наименование меры (мероприятия)", "Кол-во"]]
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


def _body(findings: list[Finding], object_name: str, rules_applied: int, today: date) -> str:
    headings = ["ВВЕДЕНИЕ", "1 Объект и методика контроля", "2 Результаты контроля"]
    if findings:
        headings.append("3 Рекомендации по устранению")
    headings.append("ЗАКЛЮЧЕНИЕ")
    if findings:
        headings.append("ПРИЛОЖЕНИЕ А Паспорта уязвимостей")

    out = [_title_page(object_name, today)]
    out.append(_p("СОДЕРЖАНИЕ", style="TitleCenter", page_break=True))
    out.append(_toc(headings))

    out.append(_heading("ВВЕДЕНИЕ", page_break=True))
    out.append(
        _p(
            "Настоящий отчёт содержит результаты контроля конфигураций информационной "
            f"системы «{object_name}», выполненного {_date_ru(today)} средством fstec-lint "
            f"версии {__version__}."
        )
    )
    out.append(
        _p(
            "Контроль проводился в рамках мероприятий, предусмотренных подпунктами «б» "
            "(контроль конфигураций информационных систем) и «ф» (проведение контроля "
            "уровня защищённости информации) пункта 34 Требований, утверждённых приказом "
            "ФСТЭК России от 11 апреля 2025 г. № 117."
        )
    )
    out.append(
        _p(
            "Выявленные недостатки сопоставлены с базовыми мерами пункта 63 Требований, "
            "подмерами методического документа ФСТЭК России от 12 апреля 2026 г. и, для "
            "информационных систем персональных данных, с мерами приказа ФСТЭК России "
            "от 18 февраля 2013 г. № 21. Описания уязвимостей составлены по ГОСТ Р 56545-2015."
        )
    )

    out.append(_heading("1 Объект и методика контроля", page_break=True))
    out.append(
        _p(
            f"Объектом контроля являются файлы развёртывания и конфигурации из каталога "
            f"«{object_name}»: описания Docker Compose, файлы Dockerfile, конфигурационные "
            "файлы PostgreSQL (postgresql.conf, pg_hba.conf), конфигурация сервера OpenSSH "
            "(sshd_config), модули служб systemd, параметры учётных записей и паролей "
            "(login.defs, pwquality.conf), конфигурация rsyslog и nginx."
        )
    )
    out.append(
        _p(
            f"Контроль выполнен методом статического анализа конфигурации. Применено "
            f"правил: {rules_applied}. Каждое правило связано с мерой приказа ФСТЭК России "
            "№ 117, подмерой методического документа и мерой приказа № 21; связь проверяется "
            "автоматическими тестами средства контроля."
        )
    )
    out.append(
        _p(
            "Статический анализ не позволяет определить версию программного обеспечения, "
            "аппаратную платформу и вектор CVSS. Соответствующие элементы паспортов "
            "уязвимостей отмечены как не определяемые."
        )
    )

    out.append(_heading("2 Результаты контроля", page_break=True))
    if not findings:
        out.append(_p("В результате контроля уязвимостей конфигурации не выявлено."))
    else:
        out.append(
            _p(
                f"В результате контроля выявлено уязвимостей конфигурации: {len(findings)}. "
                "Распределение по степени опасности приведено в таблице 1, по мерам "
                "приказа ФСТЭК России № 117 — в таблице 2, перечень — в таблице 3. "
                "Паспорта уязвимостей приведены в приложении А."
            )
        )
        out.append(_caption("Таблица 1 — Распределение уязвимостей по степени опасности"))
        out.append(_table(_by_severity(findings), [6000, 3355]))
        out.append(_caption("Таблица 2 — Распределение уязвимостей по мерам защиты информации"))
        out.append(_table(_by_measure(findings), [1900, 6055, 1400]))
        out.append(_caption("Таблица 3 — Перечень выявленных уязвимостей"))
        out.append(_table(_findings_table(findings, today), [450, 1950, 2350, 1600, 2005, 1000]))

        out.append(_heading("3 Рекомендации по устранению", page_break=True))
        out.append(
            _p(
                "Рекомендации сгруппированы по правилам и упорядочены по степени "
                "опасности (таблица 4)."
            )
        )
        out.append(_caption("Таблица 4 — Рекомендации по устранению уязвимостей"))
        out.append(_table(_remediation_table(findings), [1000, 2500, 855, 5000]))

    out.append(_heading("ЗАКЛЮЧЕНИЕ", page_break=True))
    if findings:
        critical = sum(1 for f in findings if f.rule.severity == Severity.CRITICAL)
        out.append(
            _p(
                f"По результатам контроля выявлено уязвимостей конфигурации: {len(findings)}, "
                f"из них критического уровня опасности: {critical}. Рекомендуется устранить "
                "уязвимости в соответствии с разделом 3 и провести повторный контроль."
            )
        )
    else:
        out.append(_p("По результатам контроля уязвимостей конфигурации не выявлено."))
    out.append(
        _p(
            "Средство контроля не является средством защиты информации и не заменяет "
            "аттестацию информационной системы. Результаты относятся к конфигурации, "
            "представленной в файлах, и не подтверждают состояние работающей системы."
        )
    )

    if findings:
        out.append(_p("ПРИЛОЖЕНИЕ А", style="Heading1", page_break=True))
        out.append(_p("(обязательное)", align="center"))
        out.append(_p("Паспорта уязвимостей", style="TitleCenter"))
        for index, f in enumerate(findings, start=1):
            rows = [[name, value] for name, value in passport.passport_rows(f, index, today)]
            out.append(_caption(f"Таблица А.{index} — Паспорт уязвимости {rows[1][1]}"))
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


STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{W_NS}">
<w:docDefaults>
<w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" w:eastAsia="Times New Roman"/><w:sz w:val="28"/><w:szCs w:val="28"/><w:lang w:val="ru-RU"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="360" w:lineRule="auto"/></w:pPr></w:pPrDefault>
</w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:pPr><w:ind w:firstLine="709"/><w:jc w:val="both"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:after="240"/><w:ind w:firstLine="0"/><w:jc w:val="center"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Section"><w:name w:val="Section"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:after="240"/><w:jc w:val="left"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TitleCenter"><w:name w:val="Title Center"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:after="240"/><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr><w:rPr><w:b/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="caption"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240"/><w:ind w:firstLine="0"/><w:jc w:val="left"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:line="240" w:lineRule="auto"/><w:ind w:firstLine="0"/><w:jc w:val="left"/></w:pPr><w:rPr><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="TOC1"><w:name w:val="toc 1"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:firstLine="0"/><w:jc w:val="left"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:firstLine="0"/><w:jc w:val="center"/></w:pPr></w:style>
</w:styles>"""

FOOTER = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="{W_NS}"><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>2</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>"""

SETTINGS = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="{W_NS}"><w:updateFields w:val="true"/><w:defaultTabStop w:val="709"/></w:settings>"""

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>"""

DOCUMENT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rIdSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>"""


def _core(object_name: str, today: date) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{escape('Отчёт о результатах контроля конфигураций: ' + object_name)}</dc:title>"
        f"<dc:creator>fstec-lint {__version__}</dc:creator>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{today.isoformat()}T00:00:00Z</dcterms:created>'
        "</cp:coreProperties>"
    )


def render(
    findings: list[Finding],
    object_name: str,
    rules_applied: int,
    today: date | None = None,
) -> bytes:
    today = today or date.today()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("_rels/.rels", ROOT_RELS)
        archive.writestr("docProps/core.xml", _core(object_name, today))
        archive.writestr("word/_rels/document.xml.rels", DOCUMENT_RELS)
        archive.writestr("word/styles.xml", STYLES)
        archive.writestr("word/settings.xml", SETTINGS)
        archive.writestr("word/footer1.xml", FOOTER)
        archive.writestr(
            "word/document.xml",
            _document(_body(findings, object_name, rules_applied, today)),
        )
    return buffer.getvalue()
