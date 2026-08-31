from __future__ import annotations

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
