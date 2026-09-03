from __future__ import annotations

from pathlib import Path

from .base import ConfigMap


def parse_systemd_unit(path: Path) -> dict[str, ConfigMap]:
    """Разбирает юнит systemd (*.service) в dict {секция: ConfigMap}.

    При повторе ключа внутри секции побеждает последнее вхождение —
    этого достаточно для проверки boolean/одиночных директив вроде
    NoNewPrivileges или User.
    """
    sections: dict[str, ConfigMap] = {}
    current: ConfigMap | None = None
    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                current = sections.setdefault(line[1:-1].strip(), ConfigMap())
                continue
            if current is None or "=" not in line:
                continue
            key, value = line.split("=", 1)
            current.set(key.strip(), value.strip(), lineno)
    return sections
