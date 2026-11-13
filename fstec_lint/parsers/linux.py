"""Файлы подсистемы аутентификации и журналирования Linux.

login.defs и /etc/default/useradd — параметры учётных записей
(shadow-utils), pwquality.conf — требования к сложности паролей
(libpwquality), rsyslog.conf — сбор и пересылка событий.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .base import BoundedReader, ConfigMap, SourceLine

MAX_INCLUDE_DEPTH = 16


def parse_login_defs(path: Path) -> ConfigMap:
    """login.defs: «КЛЮЧ значение», комментарий — строка с '#'.

    При повторе действует последнее значение: так читает файл getdef()
    из shadow-utils.
    """
    config = ConfigMap()
    for lineno, raw in enumerate(BoundedReader(path.parent).read(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            config.set(parts[0].upper(), parts[1].strip(), lineno)
    return config


def parse_pwquality(
    path: Path, scan_root: Path | None = None, fragments: tuple[Path, ...] | None = None
) -> ConfigMap:
    """pwquality.conf: «ключ = значение»; при повторе действует последнее."""
    config = ConfigMap()
    reader = BoundedReader(scan_root or path.parent)
    if path.name == "pwquality.conf":
        extra = reader.expand("pwquality.conf.d/*.conf", path.parent.resolve())
        files = (*extra, path)
    else:
        files = fragments if fragments is not None else (path,)
    for file in files:
        for lineno, raw in enumerate(reader.read(file).splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            key, sep, value = line.partition("=")
            key = key.strip().lower()
            mark = lineno if file == path else SourceLine(lineno, str(file))
            config.set(key, value.strip() if sep else "", mark)
    return config


def parse_useradd_defaults(path: Path) -> ConfigMap:
    """/etc/default/useradd: «КЛЮЧ=значение»; при повторе действует последнее."""
    config = ConfigMap()
    for lineno, raw in enumerate(BoundedReader(path.parent).read(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        config.set(key.strip().upper(), value.strip().strip("\"'"), lineno)
    return config


# Пересылка событий: '@host' (UDP), '@@host' (TCP), ':omrelp:host',
# action(type="omfwd"|"omrelp"|"omhttp"|"omkafka"|"omelasticsearch" ...).
_LEGACY_FORWARD_RE = re.compile(r"^\S+\s+(@{1,2}\S+|:om(?:relp|fwd):\S+)")
_ACTION_RE = re.compile(r'\baction\s*\([^)]*type\s*=\s*"(om\w+)"', re.IGNORECASE)
_REMOTE_MODULES = frozenset({"omfwd", "omrelp", "omhttp", "omkafka", "omelasticsearch"})
_INCLUDE_LEGACY_RE = re.compile(r"^\$IncludeConfig\s+(\S+)", re.IGNORECASE)
_INCLUDE_RE = re.compile(r'\binclude\s*\(\s*file\s*=\s*"([^"]+)"', re.IGNORECASE)


def _outside_quotes(text: str, stop: int) -> bool:
    quote = ""
    escaped = False
    for char in text[:stop]:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote and char == quote:
            quote = ""
        elif not quote and char in "\"'":
            quote = char
    return not quote


def _paren_delta(text: str, quote: str, escaped: bool) -> tuple[int, str, bool]:
    depth = 0
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote and char == quote:
            quote = ""
        elif not quote and char in "\"'":
            quote = char
        elif not quote and char in "()":
            depth += 1 if char == "(" else -1
    return depth, quote, escaped


@dataclass
class RsyslogConfig:
    """Действия пересылки на удалённый сервер: (описание, строка)."""

    forwards: list[tuple[str, int]] = field(default_factory=list)
    files: list[str] = field(default_factory=list)


def _rsyslog_uncomment(text: str) -> str:
    """Remove comments without changing physical lines or quoted content."""
    out: list[str] = []
    quote = ""
    block = False
    escaped = False
    i = 0
    while i < len(text):
        c = text[i]
        nxt = text[i : i + 2]
        if block:
            if nxt == "*/":
                out.append("  ")
                i += 2
                block = False
                continue
            out.append("\n" if c == "\n" else " ")
        elif quote:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == quote:
                quote = ""
        elif nxt == "/*" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";{}"):
            out.append("  ")
            i += 2
            block = True
            continue
        elif c == "#":
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        else:
            out.append(c)
            if c in "\"'":
                quote = c
        i += 1
    if block or quote:
        raise ValueError("unterminated rsyslog comment or string")
    return "".join(out)


def parse_rsyslog(path: Path, scan_root: Path | None = None) -> RsyslogConfig:
    config = RsyslogConfig()
    _read_rsyslog(path, config, path.parent.resolve(), BoundedReader(scan_root or path.parent), ())
    return config


def _read_rsyslog(
    path: Path, config: RsyslogConfig, base: Path, reader: BoundedReader, stack: tuple[Path, ...]
) -> None:
    path = reader.checked(path)
    config.files.append(str(path))
    text = _rsyslog_uncomment(reader.read(path, stack))
    stack = (*stack, path)
    # RainerScript допускает action(...) на нескольких строках: склеиваем
    # скобки, сохраняя номер первой строки.
    buffer, start, depth = "", 0, 0
    quote, escaped = "", False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip() and depth == 0:
            continue
        if depth == 0:
            buffer, start = line, lineno
        else:
            buffer += " " + line.strip()
        delta, quote, escaped = _paren_delta(line, quote, escaped)
        depth += delta
        if depth > 0 or quote:
            continue
        depth = 0
        statement = buffer.strip()
        mark = SourceLine(start, str(path))
        for pattern in (_INCLUDE_LEGACY_RE, _INCLUDE_RE):
            found = pattern.search(statement)
            if found and _outside_quotes(statement, found.start()):
                _include(found.group(1), config, base, reader, stack)
                break
        else:
            action = _ACTION_RE.search(statement)
            if (
                action
                and _outside_quotes(statement, action.start())
                and action.group(1).lower() in _REMOTE_MODULES
            ):
                config.forwards.append((statement, mark))
            elif _LEGACY_FORWARD_RE.match(statement):
                config.forwards.append((statement, mark))
    if depth:
        raise ValueError("incomplete rsyslog statement")


def _include(
    value: str, config: RsyslogConfig, base: Path, reader: BoundedReader, stack: tuple[Path, ...]
) -> None:
    for file in reader.expand(value, base):
        _read_rsyslog(file, config, base, reader, stack)
