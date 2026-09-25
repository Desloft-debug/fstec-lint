import io
import zipfile
from datetime import date
from pathlib import Path
from xml.etree import ElementTree

from fstec_lint.cli import main
from fstec_lint.engine import load_rules, scan
from fstec_lint.reporters import docx

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _document(data: bytes) -> ElementTree.Element:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return ElementTree.fromstring(archive.read("word/document.xml"))


def _text(root: ElementTree.Element) -> str:
    return "\n".join("".join(t.text or "" for t in p.iter(f"{W}t")) for p in root.iter(f"{W}p"))


def test_package_has_all_parts():
    findings = scan(EXAMPLES / "vulnerable-stack").findings
    data = docx.render(findings, "vulnerable-stack", 41, today=date(2026, 9, 26))

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = set(archive.namelist())
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                ElementTree.fromstring(archive.read(name))
    assert {
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/styles.xml",
        "word/footer1.xml",
        "word/_rels/document.xml.rels",
    } <= names


def test_one_passport_table_per_finding():
    findings = scan(EXAMPLES / "vulnerable-stack").findings
    root = _document(docx.render(findings, "vulnerable-stack", 41, today=date(2026, 9, 26)))

    tables = list(root.iter(f"{W}tbl"))
    # четыре сводные таблицы в разделах 2–3 и по паспорту на находку
    assert len(tables) == 4 + len(findings)
    text = _text(root)
    assert "ПРИЛОЖЕНИЕ А" in text
    assert f"Таблица А.{len(findings)} — Паспорт уязвимости FLINT-2026-{len(findings):04d}" in text


def test_page_setup_follows_gost_7_32():
    root = _document(docx.render([], "x", 41, today=date(2026, 9, 26)))
    margins = next(root.iter(f"{W}pgMar")).attrib

    # 20 мм сверху и снизу, 30 мм слева, 15 мм справа
    assert margins[f"{W}top"] == "1134"
    assert margins[f"{W}bottom"] == "1134"
    assert margins[f"{W}left"] == "1701"
    assert margins[f"{W}right"] == "850"
    assert next(root.iter(f"{W}titlePg"), None) is not None


def test_clean_scan_has_no_appendix():
    text = _text(_document(docx.render([], "hardened-stack", 41, today=date(2026, 9, 26))))

    assert "уязвимостей конфигурации не выявлено" in text
    assert "ПРИЛОЖЕНИЕ А" not in text


def test_table_widths_fit_the_text_area():
    findings = scan(EXAMPLES / "vulnerable-stack").findings
    root = _document(docx.render(findings, "vulnerable-stack", len(load_rules())))

    for grid in root.iter(f"{W}tblGrid"):
        width = sum(int(col.attrib[f"{W}w"]) for col in grid.iter(f"{W}gridCol"))
        assert width <= 9355


def test_cli_requires_output_for_docx(capsys):
    assert main([str(EXAMPLES / "vulnerable-stack"), "--format", "docx"]) == 2
    assert "--output" in capsys.readouterr().err


def test_cli_writes_docx(tmp_path):
    out = tmp_path / "report.docx"
    code = main([str(EXAMPLES / "vulnerable-stack"), "--format", "docx", "-o", str(out)])

    assert code == 1
    assert zipfile.is_zipfile(out)
