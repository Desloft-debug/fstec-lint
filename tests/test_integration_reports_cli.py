"""All public report surfaces, CLI priorities and secret-safe baseline compatibility."""

import io
import json
import zipfile
from dataclasses import asdict
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree as ET

import pytest
from integration_helpers import cli, displayed_path, displayed_uri, write

from fstec_lint import baseline
from fstec_lint.engine import scan

SECRET = "SYNTHETIC_TEST_CREDENTIAL_31a9"
FORMATS = ["text", "json", "html", "sarif", "passport", "docx"]
SOURCES = [
    ("compose.yaml", "C004", f"services:\n  app:\n    environment: {{PASSWORD: {SECRET}}}\n", 3),
    ("Dockerfile", "D002", f"FROM alpine:3.20\nADD https://user:{SECRET}@host.invalid/a /a\n", 2),
    ("pg_hba.conf", "P002", f"host all all 0.0.0.0/0 ldap ldapbindpasswd={SECRET}\n", 1),
    (".env", "E001", f"PASSWORD={SECRET}\n", 1),
    ("nginx.conf", "N002", "http { server { autoindex on; } }\n", 1),
    ("sshd_config", "S001", "PermitRootLogin yes\n", 1),
]


def report_text(data, fmt):
    if fmt == "docx":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert all(SECRET.encode() not in archive.read(n) for n in archive.namelist())
            texts = []
            for name in archive.namelist():
                if name.endswith((".xml", ".rels")):
                    root = ET.fromstring(archive.read(name))
                    texts.append(" ".join(root.itertext()))
            return "\n".join(texts)
    return data.decode("utf-8")


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("name,rule,content,line", SOURCES, ids=[s[1] for s in SOURCES])
def test_reports_preserve_findings_and_secrecy(tmp_path, capsys, fmt, name, rule, content, line):
    path = write(tmp_path / "Проверка & tag" / name, content)
    result = scan(path, select=[rule])
    assert not result.errors and len(result.findings) == 1
    f = result.findings[0]
    assert (f.file, f.line, f.rule.id) == (str(path), line, rule)
    assert SECRET not in repr(f) + json.dumps(asdict(f)) + f.fingerprint()
    saved = baseline.render(result.findings)
    assert SECRET not in saved
    dest = tmp_path / f"report.{fmt}"
    assert (
        cli([str(path), "--select", rule, "--format", fmt, "-o", str(dest), "--fail-on", "low"])
        == 1
    )
    text = report_text(dest.read_bytes(), fmt)
    captured = capsys.readouterr()
    assert SECRET not in text + captured.out + captured.err
    assert rule in text and "Проверка" in (unquote(text) if fmt == "sarif" else text)
    if fmt == "json":
        entry = json.loads(text)[0]
        assert (entry["file"], entry["line"], entry["severity"]) == (
            displayed_path(path),
            line,
            f.rule.severity.name.lower(),
        )
    elif fmt == "sarif":
        entry = json.loads(text)["runs"][0]["results"][0]
        physical = entry["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == displayed_uri(path)
        assert physical["region"]["startLine"] == line
    elif fmt == "html":
        assert "Проверка &amp; tag" in text
    else:
        assert f"{name}:{line}" in text


def test_html_escapes_markup_without_invalid_windows_filename(tmp_path, capsys):
    # The former <tag> path is illegal on Windows. Put markup in a legal YAML
    # service key, so escaping stays tested on all platforms.
    path = write(tmp_path / "compose.yaml", 'services: {"<tag>": {privileged: true}}\n')
    assert cli([str(path), "--select", "C002", "--format", "html"]) == 1
    output = capsys.readouterr().out
    assert "&lt;tag&gt;" in output and "<tag>" not in output


@pytest.mark.parametrize("fmt", FORMATS)
def test_reports_with_no_findings(tmp_path, capsys, fmt):
    path = write(tmp_path / "compose.yaml", "services: {app: {privileged: false}}\n")
    dest = tmp_path / f"clean.{fmt}"
    assert cli([str(path), "--select", "C002", "--format", fmt, "-o", str(dest)]) == 0
    text = report_text(dest.read_bytes(), fmt)
    assert text.strip() and SECRET not in text + capsys.readouterr().err
    if fmt == "json":
        assert json.loads(text) == []
    elif fmt == "sarif":
        assert json.loads(text)["runs"][0]["results"] == []


@pytest.mark.parametrize("fmt", FORMATS)
def test_write_error_is_usage_error_and_private(tmp_path, capsys, fmt):
    path = write(tmp_path / "compose.yaml", SOURCES[0][2])
    assert cli([str(path), "--select", "C004", "--format", fmt, "--output", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.err.strip() and "Traceback" not in captured.err
    assert SECRET not in captured.out + captured.err


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize(
    "partial,fail_on,expected",
    [
        (False, "none", 3),
        (True, "none", 3),
        (True, "high", 1),
    ],
)
def test_partial_errors_are_never_clean_and_do_not_echo_input(
    tmp_path, capsys, fmt, partial, fail_on, expected
):
    write(tmp_path / "bad/compose.yaml", f"services: [unterminated {SECRET}\n")
    if partial:
        write(tmp_path / "good/compose.yaml", "services: {app: {privileged: true}}\n")
    output = tmp_path / f"report.{fmt}"
    assert (
        cli(
            [
                str(tmp_path),
                "--select",
                "C002",
                "--fail-on",
                fail_on,
                "--format",
                fmt,
                "-o",
                str(output),
            ]
        )
        == expected
    )
    captured = capsys.readouterr()
    assert captured.err.strip() and SECRET not in captured.out + captured.err
    assert "Traceback" not in captured.err
    assert SECRET not in report_text(output.read_bytes(), fmt)


@pytest.mark.parametrize("option", ["--select", "--ignore"])
def test_unknown_ids_are_usage_errors(tmp_path, capsys, option):
    write(tmp_path / "compose.yaml", "services: {}\n")
    assert cli([str(tmp_path), option, "UNKNOWN_I04"]) == 2
    assert "UNKNOWN_I04" in capsys.readouterr().err


@pytest.mark.parametrize(
    "case,rule,filename",
    [
        ("docker_ADD", "D002", "Dockerfile"),
        ("hba_LDAP", "P002", "pg_hba.conf"),
    ],
)
def test_exact_old_baseline_has_explicit_migration_and_no_false_suppression(
    tmp_path, capsys, case, rule, filename
):
    fixtures = Path(__file__).parent / "fixtures/legacy-baselines"
    path = write(tmp_path / filename, (fixtures / case / filename).read_text(encoding="utf-8"))
    payload = json.loads((fixtures / f"old-{case}-baseline.json").read_text(encoding="utf-8"))
    payload["findings"][0]["file"] = displayed_path(path)
    legacy = write(tmp_path / "legacy.json", json.dumps(payload))
    code = cli([str(path), "--select", rule, "--baseline", str(legacy), "--format", "json"])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out) == []
    assert "SYNTHETIC_REVIEW_CREDENTIAL_6df1" not in captured.out + captured.err
    assert "baseline" in captured.err
    assert json.loads(legacy.read_text(encoding="utf-8")) == payload


def test_new_baseline_is_secret_free_and_keeps_new_findings_visible(tmp_path, capsys):
    path = write(tmp_path / ".env", f"PASSWORD={SECRET}\n")
    target = tmp_path / "baseline.json"
    assert cli([str(path), "--select", "E*", "--write-baseline", str(target)]) == 0
    assert SECRET not in target.read_text(encoding="utf-8")
    assert cli([str(path), "--select", "E*", "--baseline", str(target)]) == 0
    path.write_text(f"PASSWORD={SECRET}\nNEW_TOKEN=synthetic-new\n", encoding="utf-8")
    assert cli([str(path), "--select", "E*", "--baseline", str(target)]) == 1
    assert SECRET not in capsys.readouterr().out
