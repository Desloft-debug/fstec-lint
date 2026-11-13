"""DOCX is a public binary CLI report, tested without reading raw configs again.

XML/layout assertions are structural checks, not visual or regulatory acceptance.
"""

import io
import zipfile
from datetime import date
from xml.etree import ElementTree as ET

from integration_helpers import cli, write

from fstec_lint.engine import load_rules, scan

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _render(findings):
    from fstec_lint.reporters import docx

    return docx.render(findings, "Проект <&> Unicode", len(load_rules()), today=date(2026, 11, 7))


def _document(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            if name.endswith((".xml", ".rels")):
                ET.fromstring(archive.read(name))
        assert {"[Content_Types].xml", "_rels/.rels", "word/document.xml"} <= set(
            archive.namelist()
        )
        return ET.fromstring(archive.read("word/document.xml"))


def test_package_xml_and_finding_coordinates(tmp_path):
    path = write(tmp_path / "compose.yaml", "services:\n  app:\n    privileged: true\n")
    result = scan(path, select=["C002"])
    assert not result.errors and len(result.findings) == 1
    root = _document(_render(result.findings))
    text = "\n".join(node.text or "" for node in root.iter(f"{W}t"))
    assert "C002" in text and "compose.yaml" in text and ":3" in text
    assert "Проект <&> Unicode" in text
    assert any(token in text.lower() for token in ("critical", "критич"))


def test_clean_report_is_a_valid_document():
    root = _document(_render([]))
    assert list(root.iter(f"{W}p"))
    assert "C002" not in "".join(root.itertext())


def test_page_geometry_and_tables_fit(tmp_path):
    path = write(tmp_path / "compose.yaml", "services: {app: {privileged: true}}\n")
    root = _document(_render(scan(path, select=["C002"]).findings))
    size = next(root.iter(f"{W}pgSz")).attrib
    margins = next(root.iter(f"{W}pgMar")).attrib
    available = int(size[f"{W}w"]) - int(margins[f"{W}left"]) - int(margins[f"{W}right"])
    assert available > 0
    for grid in root.iter(f"{W}tblGrid"):
        assert sum(int(col.attrib[f"{W}w"]) for col in grid) <= available


def test_cli_requires_output_for_docx(tmp_path, capsys):
    path = write(tmp_path / "compose.yaml", "services: {}\n")
    assert cli([str(path), "--format", "docx"]) == 2
    assert "--output" in capsys.readouterr().err


def test_cli_binary_output_with_and_without_findings(tmp_path):
    path = write(tmp_path / "compose.yaml", "services: {app: {privileged: true}}\n")
    output = tmp_path / "report.docx"
    assert cli([str(path), "--select", "C002", "--format", "docx", "-o", str(output)]) == 1
    _document(output.read_bytes())
    path.write_text("services: {app: {privileged: false}}\n", encoding="utf-8")
    assert cli([str(path), "--select", "C002", "--format", "docx", "-o", str(output)]) == 0
    _document(output.read_bytes())
