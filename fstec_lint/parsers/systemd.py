from __future__ import annotations

from pathlib import Path


def parse_systemd_unit(path: Path) -> dict[str, dict[str, str]]:
    """Разбирает юнит systemd (*.service) в dict {секция: {ключ: значение}}.

    При повторе ключа внутри секции побеждает последнее вхождение —
    этого достаточно для проверки boolean/одиночных директив вроде
    NoNewPrivileges или User.
    """
    sections: dict[str, dict[str, str]] = {}
    current = None
    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                sections.setdefault(current, {})
                continue
            if current is None or "=" not in line:
                continue
            key, value = line.split("=", 1)
            sections[current][key.strip()] = value.strip()
    return sections
