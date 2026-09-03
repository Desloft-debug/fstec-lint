"""Общие структуры для парсеров конфигов."""

from __future__ import annotations


class ConfigMap(dict[str, str]):
    """Словарь параметров конфига, помнящий строку, где задан каждый ключ.

    Наследник dict, а не отдельная структура: проверки продолжают
    работать с привычным settings.get(...), а номер строки доступен там,
    где он нужен для отчёта (SARIF, text).
    """

    def __init__(self) -> None:
        super().__init__()
        self.lines: dict[str, int] = {}

    def set(self, key: str, value: str, line: int) -> None:
        self[key] = value
        self.lines[key] = line

    def line(self, key: str) -> int | None:
        return self.lines.get(key)
