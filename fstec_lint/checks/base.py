"""Общий тип результата проверки.

Проверка возвращает (location, detail, line): location — стабильный
адрес находки внутри файла (по нему считается отпечаток для baseline),
line — номер строки для отчётов, None если парсер его не знает.
"""

from __future__ import annotations

CheckResult = tuple[str, str, "int | None"]


def config_line(settings: object, key: str) -> int | None:
    """Строка, где задан ключ, если конфиг разобран парсером с ConfigMap.

    Проверкам передают и обычный dict (юнит-тесты, частичные данные),
    поэтому наличие номеров строк не обязательно.
    """
    line = getattr(settings, "line", None)
    return line(key) if callable(line) else None
