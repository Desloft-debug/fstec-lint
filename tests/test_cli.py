"""Поведение самого CLI: форматы, --output, коды выхода, пути в отчётах."""

import json

from fstec_lint import __version__
from fstec_lint.cli import main

COMPOSE = """services:
  db:
    image: postgres:latest
    privileged: true
"""


def _project(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(COMPOSE, encoding="utf-8")
    return tmp_path


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as exit_error:
        assert exit_error.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_path_exits_2(tmp_path, capsys):
    assert main([str(tmp_path / "нет-такого")]) == 2
    assert "путь не найден" in capsys.readouterr().err


def test_json_format_is_machine_readable(tmp_path, capsys):
    _project(tmp_path)

    main([str(tmp_path), "--format", "json", "--fail-on", "none"])

    payload = json.loads(capsys.readouterr().out)
    assert {"rule_id", "severity", "file", "line", "measure"} <= set(payload[0])


def test_report_paths_are_relative_to_cwd(tmp_path, monkeypatch, capsys):
    _project(tmp_path)
    monkeypatch.chdir(tmp_path)

    main([".", "--format", "json", "--fail-on", "none"])
    payload = json.loads(capsys.readouterr().out)

    assert payload[0]["file"] == "docker-compose.yml", "абсолютные пути непереносимы между машинами"


def test_output_file_is_written(tmp_path, capsys):
    _project(tmp_path)
    report = tmp_path / "report.html"

    main([str(tmp_path), "--format", "html", "--output", str(report), "--fail-on", "none"])

    assert capsys.readouterr().out == ""
    assert "<!doctype html>" in report.read_text(encoding="utf-8")


def test_fail_on_threshold_is_respected(tmp_path):
    _project(tmp_path)

    assert main([str(tmp_path), "--fail-on", "critical"]) == 1  # C002 — critical
    assert main([str(tmp_path), "--fail-on", "critical", "--ignore", "C002"]) == 0


def test_list_rules_respects_select(tmp_path, capsys):
    main(["--list-rules", "--format", "json", "--select", "S0*"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 6
    assert {rule["id"] for rule in payload["rules"]} == {f"S00{n}" for n in range(1, 7)}
