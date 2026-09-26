"""Основной конфигурационный файл Postfix (main.cf)."""

from __future__ import annotations

from pathlib import Path

from .base import ConfigMap


def parse_postfix_main(path: Path) -> ConfigMap:
    """main.cf: «параметр = значение».

    Строка, начинающаяся с пробела, продолжает предыдущее значение.
    Комментарий — строка, первый непробельный символ которой «#».
    При повторе параметра действует последнее значение, как в postconf.
    """
    config = ConfigMap()
    key: str | None = None
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if raw[0] in " \t" and key is not None:
                line = config.line(key) or lineno
                config.set(key, f"{config[key]} {raw.strip()}".strip(), line)
                continue
            name, sep, value = raw.partition("=")
            if not sep:
                key = None
                continue
            key = name.strip()
            config.set(key, value.strip(), lineno)
    return config
