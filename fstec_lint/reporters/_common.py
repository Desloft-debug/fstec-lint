"""Report context only; reporters never open scanned configuration files.

Finding fields must already be sanitized by the engine/checks. A list retains
the legacy format contract; ScanResult adds completion and suppression context.
Exception messages are deliberately not copied into saved reports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..models import Finding

if TYPE_CHECKING:
    from ..engine import ScanResult

LIMITATIONS = (
    "Результат относится к выбранным файлам и правилам с учётом фильтров, "
    "suppression и baseline. Отсутствие находок не подтверждает состояние "
    "работающей системы, соответствие требованиям или прохождение аттестации. "
    "Нормативные привязки правил требуют проверки применимости."
)
ERROR_MESSAGE = "Не удалось полностью проверить файл."


def relative_file(file: str) -> str:
    try:
        relative = os.path.relpath(file, start=os.getcwd())
    except ValueError:
        return file
    return file if relative.split(os.sep, 1)[0] == os.pardir else relative


@dataclass(frozen=True)
class ReportData:
    findings: list[Finding]
    errors: tuple[tuple[str, str], ...] = ()
    suppressed: int = 0
    has_context: bool = False

    def notes(self) -> list[str]:
        lines = []
        if self.has_context:
            lines.append(
                "Сканирование неполное: ошибок — " + str(len(self.errors))
                if self.errors
                else "Сканирование завершено без зарегистрированных ошибок."
            )
            lines.append(f"Подавлено inline-комментариями: {self.suppressed}.")
        else:
            lines.append("Статус полноты сканирования не передан.")
        lines.extend(f"{file}: {message}" for file, message in self.errors)
        lines.append(LIMITATIONS)
        return lines


def report_data(value: list[Finding] | ScanResult) -> ReportData:
    if isinstance(value, list):
        return ReportData(value)
    return ReportData(
        value.findings,
        tuple((relative_file(error.file), ERROR_MESSAGE) for error in value.errors),
        value.suppressed,
        True,
    )
