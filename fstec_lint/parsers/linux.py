"""Файлы подсистемы аутентификации и журналирования Linux.

login.defs и /etc/default/useradd — параметры учётных записей
(shadow-utils), pwquality.conf — требования к сложности паролей
(libpwquality), rsyslog.conf — сбор и пересылка событий.
"""

from __future__ import annotations

import glob
import re
from dataclasses import dataclass, field
from pathlib import Path

from .base import ConfigMap, SourceLine, include_pattern

MAX_INCLUDE_DEPTH = 16


def parse_login_defs(path: Path) -> ConfigMap:
    """login.defs: «КЛЮЧ значение», комментарий — строка с '#'.

    При повторе действует последнее значение: так читает файл getdef()
    из shadow-utils.
    """
    config = ConfigMap()
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config.set(parts[0].upper(), parts[1].strip(), lineno)
    return config


def parse_pwquality(path: Path) -> ConfigMap:
    """pwquality.conf: «ключ = значение»; при повторе действует последнее."""
    config = ConfigMap()
    # libpwquality 1.4.1+ после основного файла читает pwquality.conf.d/*.conf
    # по алфавиту; значение из более позднего файла заменяет прежнее.
    extra = sorted((path.parent / "pwquality.conf.d").glob("*.conf"))
    for file in (path, *extra):
        with open(file, encoding="utf-8") as f:
            for lineno, raw in enumerate(f, start=1):
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
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
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


@dataclass
class RsyslogConfig:
    """Действия пересылки на удалённый сервер: (описание, строка)."""

    forwards: list[tuple[str, int]] = field(default_factory=list)
    files: list[str] = field(default_factory=list)


def parse_rsyslog(path: Path) -> RsyslogConfig:
    config = RsyslogConfig()
    _read_rsyslog(path, config, path.parent, path, (path,))
    return config


def _read_rsyslog(
    path: Path, config: RsyslogConfig, base: Path, main: Path, stack: tuple[Path, ...]
) -> None:
    config.files.append(str(path))
    text = path.read_text(encoding="utf-8")
    included = path != main
    # RainerScript допускает action(...) на нескольких строках: склеиваем
    # скобки, сохраняя номер первой строки.
    buffer, start, depth = "", 0, 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip() and depth == 0:
            continue
        if depth == 0:
            buffer, start = line, lineno
        else:
            buffer += " " + line.strip()
        depth += line.count("(") - line.count(")")
        if depth > 0:
            continue
        depth = 0
        statement = buffer.strip()
        mark = SourceLine(start, str(path)) if included else start
        for pattern in (_INCLUDE_LEGACY_RE, _INCLUDE_RE):
            found = pattern.search(statement)
            if found:
                _include(found.group(1), config, base, main, stack)
                break
        else:
            action = _ACTION_RE.search(statement)
            if action and action.group(1).lower() in _REMOTE_MODULES:
                config.forwards.append((statement, mark))
            elif _LEGACY_FORWARD_RE.match(statement):
                config.forwards.append((statement, mark))


def _include(
    value: str, config: RsyslogConfig, base: Path, main: Path, stack: tuple[Path, ...]
) -> None:
    pattern = include_pattern(value, base, "/etc")
    files = [Path(m) for m in sorted(glob.glob(pattern))] if pattern else []
    for file in (f for f in files if f.is_file()):
        if len(stack) >= MAX_INCLUDE_DEPTH:
            raise ValueError(f"include вложены глубже {MAX_INCLUDE_DEPTH} уровней")
        if file.resolve() in {p.resolve() for p in stack}:
            raise ValueError(f"циклический include: {file}")
        _read_rsyslog(file, config, base, main, (*stack, file))
