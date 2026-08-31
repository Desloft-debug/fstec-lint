from __future__ import annotations

from pathlib import Path


def parse_sshd_config(path: Path) -> dict:
    """Разбирает sshd_config в dict {директива: значение}, ключи в нижнем регистре.

    Директивы читаются только до первого блока Match — условные
    per-host/per-user переопределения внутри Match не учитываются.
    При повторе директивы побеждает первое вхождение (так же ведёт
    себя сам sshd вне Match-блоков).
    """
    settings: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            if key == "match":
                break
            if len(parts) < 2:
                continue
            if key not in settings:
                settings[key] = parts[1].strip()
    return settings
