"""Benign checks of report formats, paths and explicit scan policy."""

import json
import os

from fstec_lint.cli import main
from fstec_lint.output import visible, write_report


def test_report_is_private_and_replaces_complete_contents(tmp_path):
    report = tmp_path / "report.txt"
    write_report(report, b"first")
    write_report(report, b"second")
    assert report.read_bytes() == b"second"
    assert list(tmp_path.iterdir()) == [report]
    if os.name == "posix":
        assert report.stat().st_mode & 0o077 == 0


def test_report_does_not_replace_explicit_input(tmp_path):
    cfg = tmp_path / "Dockerfile"
    expected = b"FROM alpine:3.21\nUSER 65532\n"
    cfg.write_bytes(expected)
    assert main([str(cfg), "--output", str(cfg)]) == 2
    assert cfg.read_bytes() == expected


def test_context_distinguishes_empty_from_always_clean(tmp_path, capsys):
    assert main([str(tmp_path), "--format", "json-context", "--require-input"]) == 3
    obj = json.loads(capsys.readouterr().out)
    assert obj["partial"] and obj["files_checked"] == 0 and obj["errors"]
    assert main([str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_console_encodes_control_characters():
    assert visible("Имя\nфайла\t") == r"Имя\x0aфайла\x09"


def test_explicit_policy_skips_reading_inline_exceptions(tmp_path, capsys):
    cfg = tmp_path / "compose.yaml"
    cfg.write_text("services:\n  sample:\n    image: alpine:3.21\n", encoding="utf-8")
    assert main([str(cfg), "--select", "C020", "--no-inline-suppressions", "--strict-scope"]) == 0
    assert "Подавлено inline-комментариями: 0" in capsys.readouterr().out


def test_report_does_not_replace_scanned_config_inside_project(tmp_path):
    cfg = tmp_path / "Dockerfile"
    expected = b"FROM alpine:3.21\n"
    cfg.write_bytes(expected)
    assert main([str(tmp_path), "--output", str(cfg)]) == 2
    assert cfg.read_bytes() == expected


def test_history_schema_has_explicit_contract(tmp_path):
    import sqlite3

    from fstec_lint.history import record_run

    db = tmp_path / "history.db"
    record_run(
        db,
        project="demo",
        revision="fixture",
        tool="junit",
        version="1",
        profile="linux",
        records=[],
        errors=0,
    )
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE local_extras (id INTEGER PRIMARY KEY)")
    assert main(["history", "list", str(db), "--project", "demo"]) == 2
