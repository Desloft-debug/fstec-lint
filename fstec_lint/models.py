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
    # Код меры по приказу N 17 (утратил силу 01.03.2026). Хранится как
    # история миграции, а не как утверждение о соответствии: в приказе
    # N 117 кодов такого вида нет.
    legacy_measure: str = ""


@dataclass(frozen=True)
class Finding:
    rule: Rule
    file: str
    location: str
    detail: str
    line: int | None = None
    # Строки, на которых подавляющий комментарий гасит эту находку помимо
    # line: заголовок блока и остальные строки нарушающей директивы. В
    # отчёты не попадают и в отпечаток не входят.
    suppress_lines: tuple[int, ...] = ()

    def relative_file(self) -> str:
        """Путь относительно текущего каталога.

        Абсолютные пути непереносимы между машиной разработчика и CI, а
        baseline, SARIF и обычные отчёты должны сравниваться и там, и там.
        Если путь уходит выше текущего каталога (сканируют что-то в
        стороне от проекта), относительная запись превращается в цепочку
        '../../..' и не даёт ничего, кроме нечитаемости, — тогда честнее
        абсолютный путь.
        """
        try:
            relative = os.path.relpath(self.file, start=os.getcwd())
        except ValueError:  # разные диски на Windows
            return self.file
        if relative.split(os.sep, 1)[0] == os.pardir:
            return self.file
        return relative

    def fingerprint(self) -> str:
        """Идентификатор находки для baseline.

        Намеренно не включает ни detail, ни line: текст может меняться при
        правках формулировок, а номер строки — при любой вставке выше по
        файлу; находка при этом остаётся той же самой.
        """
        return f"{self.rule.id}|{self.relative_file()}|{self.location}"
