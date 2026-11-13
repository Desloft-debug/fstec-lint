from __future__ import annotations

import re
from pathlib import Path

from .base import BoundedReader, ConfigMap, SourceLine

# Разделитель '=' в postgresql.conf необязателен ('shared_buffers 128MB'),
# но между именем и значением обязан быть либо он, либо пробел. Прежний
# шаблон делал необязательным и то и другое, поэтому на строке из одного
# слова откатывался и выдумывал настройку: 'ssl' читалось как ss = l,
# а 'sslx' — как ssl = x, то есть как значение реального параметра.
_SETTING_RE = re.compile(r"^([A-Za-z0-9_.]+)(?:\s*=\s*|\s+)(\S.*)$")

# Вторая (устаревшая, но действующая) форма адреса в pg_hba.conf — адрес
# и сетевая маска отдельными полями: 'host all all 192.168.0.0 255.255.0.0 md5'.
_NETMASK_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_CHECKED_SETTINGS = frozenset(
    {
        "ssl",
        "listen_addresses",
        "log_connections",
        "log_disconnections",
        "password_encryption",
        "log_statement",
        "statement_timeout",
    }
)
_HBA_METHODS = frozenset(
    {
        "trust",
        "reject",
        "scram-sha-256",
        "md5",
        "password",
        "gss",
        "sspi",
        "ident",
        "peer",
        "pam",
        "ldap",
        "radius",
        "cert",
        "bsd",
        "oauth",
    }
)


def _comment_offset(line: str) -> int | None:
    """Отрезает комментарий, не трогая '#' внутри кавычек.

    log_line_prefix = '%m [%p] # ' — валидное значение, наивный split('#')
    порезал бы его посередине.
    """
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and index + 1 < len(line):
                index += 2
                continue
            if char == quote and index + 1 < len(line) and line[index + 1] == quote:
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#":
            return index
        index += 1
    return None


def _strip_comment(line: str) -> str:
    offset = _comment_offset(line)
    return line if offset is None else line[:offset]


class PostgreSQLConfig(ConfigMap):
    def __init__(self) -> None:
        super().__init__()
        self.comment_offsets: dict[str, dict[int, int]] = {}


def parse_postgresql_conf(path: Path, scan_root: Path | None = None) -> PostgreSQLConfig:
    """Разбирает postgresql.conf в ConfigMap {параметр: значение}, ключи в нижнем регистре."""
    settings = PostgreSQLConfig()
    reader = BoundedReader(scan_root or path.parent)

    def read(file: Path, stack: tuple[Path, ...]) -> None:
        file = reader.checked(file)
        text = reader.read(file, stack)
        offsets: dict[int, int] = {}
        settings.comment_offsets[str(file)] = offsets
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            offset = _comment_offset(raw_line)
            if offset is not None:
                offsets[lineno] = offset
            line = (raw_line if offset is None else raw_line[:offset]).strip()
            if not line:
                continue
            match = _SETTING_RE.match(line)
            if not match:
                if re.match(r"^(include|include_if_exists|include_dir)\b", line, re.IGNORECASE):
                    raise ValueError("invalid PostgreSQL include")
                key_match = re.match(r"^([A-Za-z0-9_.]+)(?:\s|=|$)", line)
                if key_match and key_match.group(1).lower() in _CHECKED_SETTINGS:
                    raise ValueError("invalid PostgreSQL setting")
                continue
            key, value = match.group(1).lower(), match.group(2).strip()
            if key in {"include", "include_if_exists", "include_dir"}:
                if len(value) < 2 or value[0] != "'" or value[-1] != "'":
                    raise ValueError("invalid PostgreSQL include")
                target = reader.checked(file.parent / value[1:-1].replace("''", "'"))
                if key == "include_dir":
                    if not target.is_dir():
                        raise ValueError("include directory missing")
                    children = reader.postgresql_include_dir(target)
                    for child in children:
                        read(child, (*stack, file))
                elif key != "include_if_exists" or target.exists():
                    read(target, (*stack, file))
                continue
            if key in _CHECKED_SETTINGS:
                if value.startswith("'"):
                    if not re.fullmatch(r"'(?:[^'\\]|\\.|'')*'", value):
                        raise ValueError("invalid PostgreSQL setting")
                elif "'" in value or '"' in value or any(c.isspace() for c in value):
                    raise ValueError("invalid PostgreSQL setting")
            value = value.strip().strip("'\"")
            settings.set(
                key, value, lineno if file == path.resolve() else SourceLine(lineno, str(file))
            )

    read(path, ())
    return settings


def _hba_tokens(line: str) -> list[str]:
    """Split HBA fields while preserving whitespace and # inside double quotes."""
    tokens: list[str] = []
    token = ""
    quoted = False
    present = False
    i = 0
    while i < len(line):
        char = line[i]
        if char == '"':
            if quoted and i + 1 < len(line) and line[i + 1] == '"':
                token += '""'
                i += 2
                continue
            quoted = not quoted
            token += char
            present = True
        elif not quoted and char == "#":
            break
        elif not quoted and char.isspace():
            if present:
                tokens.append(token)
                token = ""
                present = False
        else:
            token += char
            present = True
        i += 1
    if quoted:
        raise ValueError("invalid pg_hba quoting")
    if present:
        tokens.append(token)
    return tokens


def _hba_comment_start(line: str) -> int:
    quoted = False
    index = 0
    while index < len(line):
        if line[index] == '"':
            if quoted and index + 1 < len(line) and line[index + 1] == '"':
                index += 2
                continue
            quoted = not quoted
        elif line[index] == "#" and not quoted:
            return index
        index += 1
    return len(line)


def parse_pg_hba(path: Path) -> list[dict]:
    """Разбирает pg_hba.conf в список записей {type, database, user, address, method, options}."""
    records: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\r\n")
            # PostgreSQL joins even comments and quoted strings before parsing.
            # Reject this form until that preprocessing is supported, rather
            # than misinterpret a commented continuation as a new record.
            if line.endswith("\\"):
                raise ValueError("unsupported pg_hba continuation")
            line = line[: _hba_comment_start(line)]
            parts = _hba_tokens(line)
            if not parts:
                continue
            if len(parts) < 3:
                raise ValueError("invalid pg_hba record")

            conn_type = parts[0]
            database = parts[1]
            user = parts[2]

            if conn_type == "local":
                if len(parts) < 4:
                    raise ValueError("invalid pg_hba record")
                address = None
                method = parts[3] if len(parts) > 3 else ""
                options = parts[4:]
            else:
                if conn_type not in {"host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"}:
                    raise ValueError("unsupported pg_hba record")
                if len(parts) < 5:
                    raise ValueError("invalid pg_hba record")
                # 'адрес маска' занимает два поля, метод сдвинут вправо.
                # Иначе методом становилась маска, а 'trust' уезжал в
                # options, и P001 не срабатывал на входе без пароля.
                if _NETMASK_RE.match(parts[4]) and "/" not in parts[3]:
                    if len(parts) < 6:
                        raise ValueError("invalid pg_hba record")
                    address = f"{parts[3]} {parts[4]}"
                    method = parts[5]
                    options = parts[6:]
                else:
                    address = parts[3]
                    method = parts[4]
                    options = parts[5:]

            if method not in _HBA_METHODS:
                raise ValueError("unsupported pg_hba authentication method")
            records.append(
                {
                    "type": conn_type,
                    "database": database,
                    "user": user,
                    "address": address,
                    "method": method,
                    "options": options,
                    "raw": line,
                    "line": lineno,
                }
            )
    return records
