"""Поведение сканера на «грязном» дереве: битые файлы, чужие каталоги, исключения."""

from pathlib import Path

from fstec_lint.cli import main
from fstec_lint.engine import discover_files, scan

VULNERABLE_COMPOSE = """
services:
  db:
    image: postgres:latest
    privileged: true
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_broken_yaml_is_reported_not_raised(tmp_path):
    _write(tmp_path / "docker-compose.yml", 'services:\n  web:\n   image: "nginx\n    bad: [\n')

    result = scan(tmp_path)

    assert result.findings == []
    assert len(result.errors) == 1
    assert result.errors[0].file.endswith("docker-compose.yml")
    assert "\n" not in result.errors[0].message


def test_binary_file_does_not_stop_the_scan(tmp_path):
    (tmp_path / "app.service").write_bytes(b"\x00\x81\x82 not text")
    _write(tmp_path / "docker-compose.yml", VULNERABLE_COMPOSE)

    result = scan(tmp_path)

    assert len(result.errors) == 1
    assert result.errors[0].file.endswith("app.service")
    # остальные файлы всё равно проверены
    assert any(f.rule.id == "C002" for f in result.findings)


def test_vendor_directories_are_skipped_by_default(tmp_path):
    _write(tmp_path / "node_modules" / "pkg" / "docker-compose.yml", VULNERABLE_COMPOSE)
    _write(tmp_path / ".git" / "docker-compose.yml", VULNERABLE_COMPOSE)
    _write(tmp_path / ".venv" / "lib" / "docker-compose.yml", VULNERABLE_COMPOSE)

    assert discover_files(tmp_path)["compose"] == []
    assert scan(tmp_path).findings == []


def test_exclude_glob_by_directory_name(tmp_path):
    _write(tmp_path / "fixtures" / "docker-compose.yml", VULNERABLE_COMPOSE)
    _write(tmp_path / "docker-compose.yml", VULNERABLE_COMPOSE)

    assert len(discover_files(tmp_path)["compose"]) == 2
    assert len(discover_files(tmp_path, exclude=["fixtures"])["compose"]) == 1


def test_exclude_glob_by_path(tmp_path):
    _write(tmp_path / "deploy" / "staging" / "docker-compose.yml", VULNERABLE_COMPOSE)
    _write(tmp_path / "deploy" / "prod" / "docker-compose.yml", VULNERABLE_COMPOSE)

    remaining = discover_files(tmp_path, exclude=["deploy/staging/*"])["compose"]

    assert [p.parent.name for p in remaining] == ["prod"]


def test_scanning_a_single_file_still_works(tmp_path):
    target = _write(tmp_path / "docker-compose.yml", VULNERABLE_COMPOSE)
    assert any(f.rule.id == "C002" for f in scan(target).findings)


def test_cli_returns_3_on_unreadable_file(tmp_path, capsys):
    (tmp_path / "app.service").write_bytes(b"\x00\x81\x82")

    exit_code = main([str(tmp_path), "--fail-on", "none"])

    captured = capsys.readouterr()
    assert exit_code == 3, "ошибка инструмента не должна выглядеть как обычные находки (код 1)"
    assert "не удалось разобрать" in captured.err


def test_cli_returns_1_on_findings_and_0_when_clean(tmp_path):
    _write(tmp_path / "docker-compose.yml", VULNERABLE_COMPOSE)
    assert main([str(tmp_path), "--fail-on", "high"]) == 1
    assert main([str(tmp_path), "--fail-on", "none"]) == 0
