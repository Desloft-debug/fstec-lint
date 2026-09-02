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
        return cls[value.upper()]


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


@dataclass(frozen=True)
class Finding:
    rule: Rule
    file: str
    location: str
    detail: str

    def relative_file(self) -> str:
        """Путь относительно текущего каталога.

        Абсолютные пути непереносимы между машиной разработчика и CI, а
        baseline и SARIF должны сравниваться и там, и там.
        """
        try:
            return os.path.relpath(self.file, start=os.getcwd())
        except ValueError:  # разные диски на Windows
            return self.file

    def fingerprint(self) -> str:
        """Идентификатор находки для baseline.

        Намеренно не включает detail: текст может меняться при правках
        формулировок, а находка при этом остаётся той же самой.
        """
        return f"{self.rule.id}|{self.relative_file()}|{self.location}"
