from __future__ import annotations

from pathlib import Path

from .base import ConfigMap

# systemd считает комментарием строку, которая ЦЕЛИКОМ начинается с '#'
# или ';'. В середине значения это обычные символы, и вырезание хвоста по
# ним рвало настоящие значения:
#   Environment="PATH=/usr/local/bin;/usr/bin" -> '"PATH=/usr/local/bin'
#   ExecStart=/bin/sh -c 'setup ; run'         -> "/bin/sh -c 'setup"
COMMENT_PREFIXES = ("#", ";")


def _logical_lines(raw_lines: list[str]) -> list[tuple[int, str]]:
    """Склеивает продолжения строк ('\\' в конце) в логические директивы.

    Иначе парсер терял хвост значения и заводил ключи из кусков команды:
    '--user' из 'ExecStart=/x \\' + '--user=app'.
    """
    logical: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for lineno, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith(COMMENT_PREFIXES)):
            continue
        if not buffer:
            start = lineno
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        logical.append((start, buffer + stripped))
        buffer = ""
    if buffer:
        logical.append((start, buffer.strip()))
    return logical


def parse_systemd_unit(path: Path) -> dict[str, ConfigMap]:
    """Разбирает юнит systemd (*.service) в dict {секция: ConfigMap}.

    При повторе ключа внутри секции побеждает последнее вхождение —
    этого достаточно для проверки boolean/одиночных директив вроде
    NoNewPrivileges или User.
    """
    sections: dict[str, ConfigMap] = {}
    current: ConfigMap | None = None
    with open(path, encoding="utf-8") as f:
        raw_lines = f.read().splitlines()

    for lineno, line in _logical_lines(raw_lines):
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), ConfigMap())
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        current.set(key.strip(), value.strip(), lineno)
    return sections
