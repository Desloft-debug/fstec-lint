"""Русскоязычный локальный режим: один прогон и необязательное сохранение."""

from __future__ import annotations

import os
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, TextIO

from .models import Severity
from .output import visible, write_report
from .reporters._common import LIMITATIONS

if TYPE_CHECKING:
    from .engine import ScanResult

_LABELS = {
    Severity.CRITICAL: "критических",
    Severity.HIGH: "высоких",
    Severity.MEDIUM: "средних",
    Severity.LOW: "низких",
}


class _PathInputError(ValueError):
    pass


def _prompt(stdin: TextIO, stdout: TextIO, label: str) -> str:
    print(label, end="", file=stdout, flush=True)
    line = stdin.readline()
    if line == "":
        raise EOFError
    return line.rstrip("\r\n")


def _path(value: str) -> Path | None:
    value = value.strip()
    if len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]:
        value = value[1:-1]
    if not value:
        return None
    windows_path = PureWindowsPath(value)
    if windows_path.drive.startswith("\\\\") or value.startswith(("\\\\", "//")):
        raise _PathInputError(
            "укажите локальный путь, сетевые пути и пути устройств не поддерживаются"
        )
    if os.name != "nt" and windows_path.drive:
        raise _PathInputError("путь с буквой диска Windows нужно открыть на Windows")
    if os.name == "nt" and any(
        ":" in part or PureWindowsPath(part).is_reserved()
        for part in windows_path.parts[int(bool(windows_path.anchor)) :]
    ):
        raise _PathInputError("путь к устройству или потоку файла не поддерживается")
    return Path(value).expanduser().absolute()


def _file_label(filename: str, base: Path) -> str:
    path = Path(filename)
    try:
        relative = path.absolute().relative_to(base)
        if ".." not in relative.parts:
            return visible(relative.as_posix())
    except ValueError:
        pass
    return "(вне выбранного каталога)"


def _report(result: ScanResult, *, base: Path) -> str:
    lines = ["fstec-lint: локальная статическая проверка"]
    if result.files_checked == 0 and not result.errors:
        lines.append("Поддерживаемые файлы конфигурации не найдены; проверить было нечего.")
    elif result.errors:
        lines.append(f"Проверка неполная: пропуски или ошибки обработки ({len(result.errors)}).")
    else:
        lines.append("Проверка завершена без зарегистрированных ошибок.")

    lines.append(f"Файлов передано на проверку: {result.files_checked}.")
    counts = Counter(finding.rule.severity for finding in result.findings)
    summary = ", ".join(f"{label}: {counts[severity]}" for severity, label in _LABELS.items())
    lines.append(f"Находок: {len(result.findings)} ({summary}).")
    if result.suppressed:
        lines.append(f"Подавлено комментариями в конфигурациях: {result.suppressed}.")

    for finding in result.findings:
        name = _file_label(finding.file, base)
        loc = name if finding.line is None else f"{name}:{finding.line}"
        lines.extend(
            [
                f"\n[{finding.rule.severity.name}] {visible(finding.rule.id)} "
                f"{visible(finding.rule.title)}",
                f"  Файл: {loc}",
                f"  Где: {visible(finding.location)}",
                f"  Факт: {visible(finding.detail)}",
                f"  Мера ФСТЭК: {visible(finding.rule.measure)}",
                f"  Как исправить: {visible(finding.rule.remediation)}",
            ]
        )

    if result.errors:
        lines.append("\nНе удалось полностью проверить:")
        labels = sorted({_file_label(error.file, base) for error in result.errors})
        lines.extend(f"  {label}" for label in labels)
    lines.extend(["", LIMITATIONS])
    return "\n".join(lines)


def run_menu(
    run_scan: Callable[[Path], ScanResult],
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Прочитать путь без shell, показать результат и предложить локальный отчёт."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if not stdin.isatty() or not stdout.isatty():
        print(
            "Интерактивный режим требует терминал. Для автоматизации: fstec-lint <путь>.",
            file=stdout,
        )
        return 2

    print("fstec-lint: проверка конфигураций без запуска проекта.", file=stdout)
    try:
        root = _path(_prompt(stdin, stdout, "Путь к файлу или папке (Enter — выход): "))
        if root is None:
            return 0
        if not root.exists():
            print("Путь не найден. Укажите существующий файл или папку.", file=stdout)
            return 2
        if root.is_file():
            base = root.parent
        elif root.is_dir():
            base = root
        else:
            print("Укажите обычный файл или папку.", file=stdout)
            return 2
        # Нормализуем основание без раскрытия симлинков; для отчёта допустимы
        # только имена файлов относительно области проверки.
        root = Path(os.path.abspath(root))
        base = Path(os.path.abspath(base))
    except (EOFError, KeyboardInterrupt):
        print("\nПроверка отменена.", file=stdout)
        return 0
    except _PathInputError as exc:
        print(f"Недопустимый путь: {exc}.", file=stdout)
        return 2
    except (OSError, RuntimeError, ValueError):
        print("Не удалось открыть путь.", file=stdout)
        return 2

    try:
        result = run_scan(root)
    except KeyboardInterrupt:
        print("\nПроверка отменена.", file=stdout)
        return 0
    report = _report(result, base=base)
    print(f"\n{report}\n", file=stdout)

    status = 0
    if any(finding.rule.severity >= Severity.HIGH for finding in result.findings):
        status = 1
    elif result.errors or result.files_checked == 0:
        status = 3

    if os.name == "nt":
        print("Для отчёта выберите папку, доступную только вам.", file=stdout)
    try:
        destination = _path(
            _prompt(
                stdin,
                stdout,
                "Отчёт не создаётся автоматически. Путь к новому .txt-файлу "
                "(Enter — не сохранять): ",
            )
        )
        if destination is not None:
            if destination.suffix.lower() != ".txt":
                print("Для текстового отчёта укажите путь, оканчивающийся на .txt.", file=stdout)
                return 2
            write_report(destination, (report + "\n").encode("utf-8"), overwrite=False)
            print("Отчёт сохранён локально.", file=stdout)
    except (EOFError, KeyboardInterrupt):
        print("\nОтчёт не сохранён.", file=stdout)
    except _PathInputError as exc:
        print(f"Недопустимый путь: {exc}.", file=stdout)
        return 2
    except FileExistsError:
        print("Отчёт не сохранён: файл с таким именем уже существует.", file=stdout)
        return 2
    except (OSError, RuntimeError, ValueError):
        print("Не удалось сохранить отчёт. Проверьте папку и права доступа.", file=stdout)
        return 2
    return status
