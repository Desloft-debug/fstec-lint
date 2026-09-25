from __future__ import annotations

import os
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            allowed = ", ".join(level.name.lower() for level in cls)
            raise ValueError(f"неизвестная severity: {value!r} (допустимы: {allowed})") from None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    measure: str
    measure_title: str
    description: str
    remediation: str
    target: str
    orders: str = ""
    # Методический документ от 12.04.2026: подмера (ЗКО.5) и мероприятие (КК).
    submeasure: str = ""
    submeasure_title: str = ""
    activity: str = ""
    activity_title: str = ""
    # Тип недостатка, ГОСТ Р 56545-2015 п. 5.1.3.
    cwe: str = ""
    weakness_type: str = ""
    # Мера приказа N 21 для ИСПДн.
    pdn_measure: str = ""
    pdn_measure_title: str = ""


@dataclass(frozen=True)
class Finding:
    rule: Rule
    file: str
    location: str
    detail: str
    line: int | None = None
    # Дополнительные строки, где комментарий может подавить находку.
    suppress_lines: tuple[int, ...] = ()

    def relative_file(self) -> str:
        """Путь относительно текущего каталога, если файл внутри него."""
        try:
            relative = os.path.relpath(self.file, start=os.getcwd())
        except ValueError:  # разные диски на Windows
            return self.file
        if relative.split(os.sep, 1)[0] == os.pardir:
            return self.file
        return relative

    def fingerprint(self) -> str:
        """Отпечаток для baseline (без detail и line, они нестабильны)."""
        return f"{self.rule.id}|{self.relative_file()}|{self.location}"
