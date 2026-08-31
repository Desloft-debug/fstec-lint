from __future__ import annotations

import re
from pathlib import Path

_SETTING_RE = re.compile(r"^([A-Za-z0-9_.]+)\s*=?\s*(.+)$")


def parse_postgresql_conf(path: Path) -> dict:
    """Разбирает postgresql.conf в dict {параметр: значение}, ключи в нижнем регистре."""
    settings: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            match = _SETTING_RE.match(line)
            if not match:
                continue
            key, value = match.group(1).lower(), match.group(2).strip()
            value = value.strip().strip("'\"")
            settings[key] = value
    return settings


def parse_pg_hba(path: Path) -> list[dict]:
    """Разбирает pg_hba.conf в список записей {type, database, user, address, method, options, raw}."""
    records: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
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
                }
            )
    return records
