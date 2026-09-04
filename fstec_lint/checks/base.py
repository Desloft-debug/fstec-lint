"""Тип результата проверки и предикаты, общие для нескольких правил."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

# Четвёртый элемент необязателен: это строки, на которых подавляющий
# комментарий гасит находку помимо самой line. Нужен только compose, где
# '# fstec-lint: ignore' пишут и у директивы, и на заголовке сервиса.
CheckResult = tuple[str, str, "int | None"] | tuple[str, str, "int | None", "tuple[int, ...]"]

# Sequence, а не list: list инвариантен, и проверка, собирающая только
# трёхэлементные кортежи, не подошла бы под объединение выше.
CheckResults = Sequence[CheckResult]

ROOT_UIDS = frozenset({"root", "0"})


def config_line(settings: object, key: str) -> int | None:
    """Строка, где задан ключ. None, если парсер номеров строк не хранит."""
    line = getattr(settings, "line", None)
    return line(key) if callable(line) else None


def is_root_user(value: object) -> bool:
    """root в любой записи: 'root', 'ROOT', '0', 'root:root', '0:0', в кавычках.

    Один предикат на C001, D001 и U001 — расходиться в том, что считать
    root, эти правила не должны.
    """
    uid = str(value).strip().strip("\"'").split(":", 1)[0].strip().lower()
    return uid in ROOT_UIDS


def as_list(value: object) -> list:
    """Поле, которое по схеме compose должно быть списком.

    Скаляр заворачивается в список, а не обходится по буквам: иначе
    'volumes: "/etc:/data"' давало ложное срабатывание на символе '/' и
    пропускало docker.sock. Отображение — одна запись длинного
    синтаксиса, забытая без дефиса.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        return [value]
    return list(value)
