"""Общие структуры для парсеров конфигов."""

from __future__ import annotations

from pathlib import Path, PurePosixPath


class SourceLine(int):
    """Номер строки в подключённом файле (Include).

    Ведёт себя как int, поэтому проверки передают его дальше как обычный
    номер строки, а движок по атрибуту file относит находку к нужному файлу.
    """

    file: str

    def __new__(cls, value: int, file: str) -> SourceLine:
        obj = super().__new__(cls, value)
        obj.file = file
        return obj


class ConfigMap(dict[str, str]):
    """dict параметров, который помнит строку каждого ключа."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: dict[str, int] = {}

    def set(self, key: str, value: str, line: int) -> None:
        self[key] = value
        self.lines[key] = line

    def line(self, key: str) -> int | None:
        return self.lines.get(key)


def include_pattern(value: str, base: Path, system_dir: str) -> str | None:
    """Путь директивы include в проверяемом дереве.

    Относительный путь берётся от каталога основного файла (base).
    Абсолютный используется как есть, если лежит внутри base; путь под
    system_dir (например, /etc/nginx) переносится в base. Прочие
    абсолютные пути указывают на файлы другой системы и не читаются.
    """
    path = PurePosixPath(value)
    if not path.is_absolute():
        return str(base / path)
    try:
        path.relative_to(base.resolve().as_posix())
        return value
    except ValueError:
        pass
    try:
        return str(base / path.relative_to(system_dir))
    except ValueError:
        return None
