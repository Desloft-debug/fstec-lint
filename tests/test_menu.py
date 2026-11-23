from __future__ import annotations

import os
from io import StringIO
from pathlib import Path

import pytest

from fstec_lint.engine import ScanError, ScanResult, scan
from fstec_lint.menu import run_menu
from fstec_lint.models import Finding, Rule, Severity


class Terminal(StringIO):
    def isatty(self) -> bool:
        return True


class InterruptedTerminal(Terminal):
    def readline(self, size: int = -1) -> str:
        raise KeyboardInterrupt


def unexpected_scan(root: Path) -> ScanResult:
    pytest.fail(f"Unexpected scan of {root}")


@pytest.mark.parametrize("stream", [Terminal(""), Terminal("\n"), InterruptedTerminal()])
def test_cancel_or_eof_does_not_scan(stream: Terminal) -> None:
    assert run_menu(unexpected_scan, stdin=stream, stdout=Terminal()) == 0


def test_not_a_terminal_is_rejected_without_scanning() -> None:
    out = Terminal()
    assert run_menu(unexpected_scan, stdin=StringIO("x\n"), stdout=out) == 2
    assert "требует терминал" in out.getvalue()
    assert "Путь к файлу" not in out.getvalue()


def test_missing_path_and_network_path_do_not_scan(tmp_path: Path) -> None:
    for path, hint in (
        (str(tmp_path / "missing"), "Путь не найден"),
        (r"\\remote\share", "сетевые пути"),
    ):
        out = Terminal()
        assert run_menu(unexpected_scan, stdin=Terminal(path + "\n"), stdout=out) == 2
        assert hint in out.getvalue()


def test_actual_scan_of_double_quoted_path_with_spaces(tmp_path: Path) -> None:
    root = tmp_path / "проект с пробелами"
    root.mkdir()
    script = root / "Dockerfile"
    script.write_text("FROM alpine:latest\nRUN touch must-not-exist\n", encoding="utf-8")

    out = Terminal()
    run_menu(scan, stdin=Terminal(f'"{script}"\n\n'), stdout=out)

    assert "Файлов передано на проверку: 1" in out.getvalue()
    assert "Файл: Dockerfile" in out.getvalue()
    assert str(root) not in out.getvalue()
    assert sorted(path.name for path in root.iterdir()) == ["Dockerfile"]


def test_empty_folder_is_not_a_clean_scan(tmp_path: Path) -> None:
    out = Terminal()
    assert run_menu(scan, stdin=Terminal(f"{tmp_path}\n\n"), stdout=out) == 3
    assert "проверить было нечего" in out.getvalue()
    assert "завершена без зарегистрированных ошибок" not in out.getvalue()


def test_partial_scan_reports_coverage_and_does_not_print_raw_error(tmp_path: Path) -> None:
    path = tmp_path / "bad file.yaml"
    out = Terminal()
    result = ScanResult(files_checked=1, errors=[ScanError(str(path), "secret-token")])
    assert run_menu(lambda _: result, stdin=Terminal(f"{tmp_path}\n"), stdout=out) == 3
    printed = out.getvalue()
    assert "Проверка неполная" in printed
    assert path.name in printed
    assert "secret-token" not in printed
    assert "Отчёт не сохранён" in printed


def test_optional_report_matches_terminal_and_is_not_rescanned(tmp_path: Path) -> None:
    count = 0
    rule = Rule("C000", "Важное\x1b[0m", Severity.HIGH, "УПД.1", "", "", "", "compose")
    finding = Finding(rule, str(tmp_path / "compose.yaml"), "service", "fact", line=3)

    def run(root: Path) -> ScanResult:
        nonlocal count
        assert root == tmp_path
        count += 1
        return ScanResult(findings=[finding], files_checked=1)

    destination = tmp_path / "отчёт с пробелом.txt"
    out = Terminal()
    assert run_menu(run, stdin=Terminal(f"'{tmp_path}'\n'{destination}'\n"), stdout=out) == 1
    assert count == 1
    saved = destination.read_text(encoding="utf-8")
    assert saved in out.getvalue()
    assert "критических: 0, высоких: 1, средних: 0, низких: 0" in saved
    assert "compose.yaml:3" in saved
    assert "\x1b" not in saved
    assert str(tmp_path) not in saved
    if os.name != "nt":
        assert destination.stat().st_mode & 0o077 == 0


def test_existing_report_is_not_overwritten(tmp_path: Path) -> None:
    destination = tmp_path / "report.txt"
    destination.write_text("existing report", encoding="utf-8")
    result = ScanResult(files_checked=1)
    out = Terminal()
    assert (
        run_menu(lambda _: result, stdin=Terminal(f"{tmp_path}\n{destination}\n"), stdout=out) == 2
    )
    assert destination.read_text(encoding="utf-8") == "existing report"
    assert "не удалось сохранить" in out.getvalue().lower() or "уже существует" in out.getvalue()
