"""Разбор .env без исполнения команд и подстановки окружения машины."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ASSIGNMENT_RE = re.compile(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:\s*)\s*(.*)$")
BARE_KEY_RE = re.compile(r"(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*(?:#.*)?$")
ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}


@dataclass(frozen=True)
class EnvEntry:
    key: str
    value: str
    line: int
    interpolate: bool = True


@dataclass(frozen=True)
class EnvFile:
    # Повторные объявления сохраняются: переопределение не удаляет секрет из файла.
    entries: tuple[EnvEntry, ...]
    comments: tuple[tuple[int, str], ...]


def _error(line: int, reason: str) -> ValueError:
    # Ни исходная строка, ни значение не должны попадать в сообщение об ошибке.
    return ValueError(f"строка {line}: {reason}")


def _quoted_value(lines: list[str], index: int, raw: str) -> tuple[str, int, str]:
    quote = raw[0]
    start = index + 1
    pos = 1
    value: list[str] = []
    while True:
        while pos < len(raw):
            char = raw[pos]
            if char == quote:
                tail = raw[pos + 1 :].strip()
                if tail and not tail.startswith("#"):
                    raise _error(start, "лишний текст после закрывающей кавычки")
                return "".join(value), index, tail
            if char == "\\" and pos + 1 < len(raw):
                following = raw[pos + 1]
                if following == quote or (quote == '"' and following in ESCAPES):
                    value.append(ESCAPES.get(following, following))
                    pos += 2
                    continue
                # Сохраняем экранированный доллар: это литерал, а не ссылка.
                value.extend((char, following))
                pos += 2
                continue
            value.append(char)
            pos += 1
        index += 1
        if index >= len(lines):
            raise _error(start, "незакрытая кавычка")
        value.append("\n")
        raw = lines[index]
        pos = 0


def parse_dotenv(path: Path) -> EnvFile:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    entries: list[EnvEntry] = []
    comments: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        raw = lines[index].lstrip()
        line = index + 1
        if not raw or raw.startswith("#"):
            if raw:
                comments.append((line, raw))
            index += 1
            continue
        match = ASSIGNMENT_RE.fullmatch(raw)
        if match is None:
            # dotenv допускает ключ без значения; это не секрет.
            if BARE_KEY_RE.fullmatch(raw):
                index += 1
                continue
            raise _error(line, "ожидалось присваивание KEY=VALUE")
        key, value = match.groups()
        interpolate = not value.startswith("'")
        if value.startswith(("'", '"')):
            value, index, comment = _quoted_value(lines, index, value)
        else:
            value = value.rstrip()
            # '#' внутри значения — часть значения, комментарий требует пробела.
            comment_match = re.search(r"(?:^|\s)#", value)
            comment = value[comment_match.start() :].strip() if comment_match else ""
            if comment_match:
                value = value[: comment_match.start()].rstrip()
        if comment:
            # У многострочного значения подавление относится к началу записи.
            comments.append((line, comment))
        entries.append(EnvEntry(key, value, line, interpolate))
        index += 1
    return EnvFile(tuple(entries), tuple(comments))
