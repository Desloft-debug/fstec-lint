"""Тип результата проверки и предикаты, общие для нескольких правил."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

# Необязательный четвёртый элемент — дополнительные строки для подавления
# комментарием (используется только в compose).
CheckResult = tuple[str, str, "int | None"] | tuple[str, str, "int | None", "tuple[int, ...]"]

# Sequence, потому что list инвариантен.
CheckResults = Sequence[CheckResult]

ROOT_UIDS = frozenset({"root", "0"})


def config_line(settings: object, key: str) -> int | None:
    """Строка, где задан ключ. None, если парсер номеров строк не хранит."""
    line = getattr(settings, "line", None)
    return line(key) if callable(line) else None


def is_root_user(value: object) -> bool:
    """root в любой записи: 'root', 'ROOT', '0', 'root:root', '0:0', в кавычках.

    Общий для C001, D001 и U001.
    """
    uid = str(value).strip().strip("\"'").split(":", 1)[0].strip().lower()
    return uid in ROOT_UIDS


def as_list(value: object) -> list:
    """Поле, которое по схеме compose должно быть списком.

    Строку оборачиваем в список (иначе её обойдут по символам), словарь
    считаем одной записью длинного синтаксиса без дефиса.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        return [value]
    return list(value)
