from __future__ import annotations

import os
from pathlib import Path

from .base import BoundedReader, ConfigMap, SourceLine

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
    buffer: list[str] = []
    start = 0
    for lineno, raw in enumerate(raw_lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(COMMENT_PREFIXES):
            continue
        if not buffer:
            start = lineno
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].rstrip())
            continue
        buffer.append(stripped)
        logical.append((start, " ".join(buffer)))
        buffer.clear()
    if buffer:
        raise ValueError("incomplete systemd continuation")
    return logical


class SystemdDropInError(ValueError):
    """The local set of overrides cannot be evaluated without guessing."""


def _local_drop_ins(entry: Path, reader: BoundedReader) -> list[Path]:
    directory = entry.parent
    stem = entry.name.removesuffix(".service")
    broader = {"service.d"}
    if "@" in stem and not stem.endswith("@"):
        broader.add(stem.split("@", 1)[0] + "@.service.d")
    for index, char in enumerate(stem):
        if char == "-":
            broader.add(stem[: index + 1] + ".service.d")
    exact = entry.name + ".d"
    for name in sorted(broader - {exact}):
        try:
            reader.local_include(directory / name)
        except FileNotFoundError:
            continue
        raise SystemdDropInError("обнаружен общий или шаблонный каталог systemd")
    try:
        fragment_dir = reader.local_include(directory / exact)
    except FileNotFoundError:
        return []
    paths: list[Path] = []
    with os.scandir(fragment_dir) as entries:
        for item in entries:
            reader.work += 1
            if reader.work > 16384:
                raise SystemdDropInError("превышен предел фрагментов systemd")
            if item.name.startswith(".") or not item.name.endswith(".conf"):
                continue
            if len(paths) >= 255:
                raise SystemdDropInError("превышен предел фрагментов systemd")
            paths.append(reader.local_include(Path(item.path)))
    return sorted(paths, key=lambda item: item.name.encode("utf-8"))


def parse_systemd_unit(path: Path, scan_root: Path | None = None) -> dict[str, ConfigMap]:
    """Scan one unit and its adjacent exact-name drop-ins, not the live manager."""
    sections: dict[str, ConfigMap] = {}
    reader = BoundedReader(scan_root or path.parent)
    entry = reader.checked(path)

    def read(source: Path) -> None:
        current: ConfigMap | None = None
        for lineno, line in _logical_lines(reader.read(source).splitlines()):
            if line.startswith("[") and line.endswith("]"):
                current = sections.setdefault(line[1:-1].strip(), ConfigMap())
                continue
            if current is None or "=" not in line:
                continue
            key, value = line.split("=", 1)
            origin = lineno if source == entry else SourceLine(lineno, str(source))
            current.set(key.strip(), value.strip(), origin)

    read(entry)
    try:
        for fragment in _local_drop_ins(entry, reader):
            read(fragment)
    except SystemdDropInError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise SystemdDropInError("не разобраны локальные переопределения systemd") from None
    return sections
