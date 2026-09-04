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
    # Методический документ ФСТЭК от 12.04.2026: подмера раздела IV
    # (ЗКО.5, УПД.2) и мероприятие раздела III (КК, ПД, БР).
    submeasure: str = ""
    submeasure_title: str = ""
    activity: str = ""
    activity_title: str = ""
    # ГОСТ Р 56545-2015, п. 5.1.3: идентификатор и наименование типа
    # недостатка — обязательные элементы описания уязвимости для работ
    # по её анализу.
    cwe: str = ""
    weakness_type: str = ""
    # Мера приказа N 21 (ИСПДн; приказ действует). Второй нормативный
    # контур: для ГИС привязка идёт по приказу N 117 и методическому
    # документу, для персональных данных — по приказу N 21.
    pdn_measure: str = ""
    pdn_measure_title: str = ""


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
        baseline и SARIF сравниваются и там, и там. Если же путь уходит
        выше текущего каталога, относительная запись вырождается в
        цепочку '../../..' — тогда лучше оставить абсолютный.
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

        Ни detail, ни line не входят: текст меняется при правках
        формулировок, номер строки — при вставке выше по файлу.
        """
        return f"{self.rule.id}|{self.relative_file()}|{self.location}"
