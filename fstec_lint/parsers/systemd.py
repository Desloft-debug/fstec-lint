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


def _scope_names(unit: str) -> list[str]:
    """Return local drop-in scopes from most to least specific."""
    stem = unit.removesuffix(".service")
    scopes: dict[str, None] = {}

    def collect(name: str) -> None:
        if name in scopes:
            return
        scopes[name] = None
        prefix, at, instance = name.partition("@")
        if at and instance:
            collect(prefix + "@")

        dash = prefix.rfind("-")
        if dash == len(prefix) - 1:
            dash = prefix.rfind("-", 0, dash)
        if dash > 0:
            suffix = at + instance if instance else ""
            collect(prefix[: dash + 1] + suffix)

    collect(stem)
    return [*(name + ".service.d" for name in scopes), "service.d"]


def _local_drop_ins(entry: Path, reader: BoundedReader) -> list[Path]:
    # Scope priority only decides a tie between equal basenames. All
    # different basenames are applied in a single lexicographic order.
    winners: dict[str, Path] = {}
    for name in _scope_names(entry.name):
        try:
            fragment_dir = reader.local_include(entry.parent / name)
        except FileNotFoundError:
            continue
        with os.scandir(fragment_dir) as entries:
            for item in entries:
                reader.work += 1
                if reader.work > 16384:
                    raise SystemdDropInError("превышен предел фрагментов systemd")
                if item.name.startswith(".") or not item.name.endswith(".conf"):
                    continue
                if item.name in winners:
                    continue
                if len(winners) >= 255:
                    raise SystemdDropInError("превышен предел фрагментов systemd")
                winners[item.name] = reader.local_include(Path(item.path))
    return [winners[name] for name in sorted(winners, key=os.fsencode)]


def parse_systemd_unit(path: Path, scan_root: Path | None = None) -> dict[str, ConfigMap]:
    """Scan one unit and adjacent drop-in scopes, not the live manager."""
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
