from __future__ import annotations

import re
from pathlib import Path

from .base import ConfigMap

# Разделитель '=' в postgresql.conf необязателен ('shared_buffers 128MB'),
# но между именем и значением обязан быть либо он, либо пробел. Прежний
# шаблон делал необязательным и то и другое, поэтому на строке из одного
# слова откатывался и выдумывал настройку: 'ssl' читалось как ss = l,
# а 'sslx' — как ssl = x, то есть как значение реального параметра.
_SETTING_RE = re.compile(r"^([A-Za-z0-9_.]+)(?:\s*=\s*|\s+)(\S.*)$")

# Вторая (устаревшая, но действующая) форма адреса в pg_hba.conf — адрес
# и сетевая маска отдельными полями: 'host all all 192.168.0.0 255.255.0.0 md5'.
_NETMASK_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _strip_comment(line: str) -> str:
    """Отрезает комментарий, не трогая '#' внутри кавычек.

    log_line_prefix = '%m [%p] # ' — валидное значение, наивный split('#')
    порезал бы его посередине.
    """
    quote: str | None = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#":
            return line[:index]
    return line


def parse_postgresql_conf(path: Path) -> ConfigMap:
    """Разбирает postgresql.conf в ConfigMap {параметр: значение}, ключи в нижнем регистре."""
    settings = ConfigMap()
    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = _strip_comment(raw_line).strip()
            if not line:
                continue
            match = _SETTING_RE.match(line)
            if not match:
                continue
            key, value = match.group(1).lower(), match.group(2).strip()
            value = value.strip().strip("'\"")
            settings.set(key, value, lineno)
    return settings


def parse_pg_hba(path: Path) -> list[dict]:
    """Разбирает pg_hba.conf в список записей {type, database, user, address, method, options}."""
    records: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            conn_type = parts[0]
            database = parts[1]
            user = parts[2]

            if conn_type == "local":
                address = None
                method = parts[3] if len(parts) > 3 else ""
                options = parts[4:]
            else:
                if len(parts) < 5:
                    continue
                # 'адрес маска' занимает два поля, и метод стоит на одну
                # позицию правее. Без этой ветки методом становилась маска,
                # а настоящий метод уезжал в options — и P001 молчал на
                # записи с 'trust', то есть на входе без пароля.
                if _NETMASK_RE.match(parts[4]) and "/" not in parts[3]:
                    if len(parts) < 6:
                        continue
                    address = f"{parts[3]} {parts[4]}"
                    method = parts[5]
                    options = parts[6:]
                else:
                    address = parts[3]
                    method = parts[4]
                    options = parts[5:]

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
