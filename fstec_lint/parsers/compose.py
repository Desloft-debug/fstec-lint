from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Ключи верхнего уровня современного compose. Файл с именем
# 'docker-compose.yml', в котором нет ни одного из них, — это формат v1,
# где сервисы лежат прямо в корне. Разбирать его как современный значит
# молча выдать «нарушений не найдено» на файле, который не проверялся.
TOP_LEVEL_KEYS = frozenset(
    {"services", "version", "volumes", "networks", "configs", "secrets", "include", "name", "x-"}
)

# Разбор чужого compose не должен быть способом положить CI на памяти.
# Раскрытие якорей ('billion laughs') PyYAML не грозит — safe_load
# переиспользует уже собранный объект якоря, а не копирует его, — но
# просто очень большой файл всё ещё читается целиком в память.
MAX_FILE_BYTES = 8 * 1024 * 1024


class ComposeFile(dict[str, Any]):
    """Разобранный compose-файл, помнящий строки объявлений.

    Номера строк берутся из узлов YAML (yaml.compose), а не из повторного
    разбора текста регуляркой, поэтому совпадают с реальным файлом при
    любых отступах и якорях.

    Помимо строки самого сервиса хранится строка каждого его ключа:
    находка о портах должна показывать строку 'ports', иначе подавляющий
    комментарий, написанный над нарушающей директивой, не работает.
    """

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        super().__init__(data or {})
        self.service_lines: dict[str, int] = {}
        # (сервис, ключ) -> (первая строка директивы, последняя строка её
        # значения). Конец нужен подавлению: комментарий пишут не только
        # у 'ports:', но и у конкретной строки внутри списка портов.
        self.key_spans: dict[tuple[str, str], tuple[int, int]] = {}

    def service_line(self, name: str) -> int | None:
        return self.service_lines.get(name)

    def key_line(self, service: str, *keys: str) -> int | None:
        """Строка первого из перечисленных ключей сервиса, иначе — строка сервиса.

        Проверка называет ключи, на которых она судит ('ports', 'volumes'),
        и получает строку самого раннего из присутствующих. Если ни одного
        нет (находка «директива отсутствует»), адресом остаётся объявление
        сервиса — привязать её больше не к чему.
        """
        starts = [
            span[0] for key in keys if (span := self.key_spans.get((service, key))) is not None
        ]
        return min(starts) if starts else self.service_lines.get(service)

    def suppression_lines(self, service: str, line: int | None) -> tuple[int, ...]:
        """Строки, на которых подавляющий комментарий гасит эту находку.

        Это заголовок сервиса (вывести сервис целиком) плюс все строки
        директивы, к которой находка относится, — чтобы комментарий,
        написанный у конкретного элемента списка, а не у самого ключа,
        тоже работал.
        """
        lines: set[int] = set()
        if (header := self.service_lines.get(service)) is not None:
            lines.add(header)
        if line is not None:
            for (name, _key), (start, end) in self.key_spans.items():
                if name == service and start <= line <= end:
                    lines.update(range(start, end + 1))
        return tuple(sorted(lines))


def _mapping(node: object) -> list[tuple[Any, Any]]:
    return node.value if isinstance(node, yaml.MappingNode) else []


def _line_marks(text: str) -> tuple[dict[str, int], dict[tuple[str, str], tuple[int, int]]]:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return {}, {}

    service_lines: dict[str, int] = {}
    key_spans: dict[tuple[str, str], tuple[int, int]] = {}
    for key_node, value_node in _mapping(root):
        if key_node.value != "services":
            continue
        for service_key, service_value in _mapping(value_node):
            name = str(service_key.value)
            service_lines[name] = service_key.start_mark.line + 1
            for field_key, field_value in _mapping(service_value):
                start = field_key.start_mark.line + 1
                # end_mark блочного узла указывает на начало следующей
                # строки, поэтому конец берётся как максимум из начала и
                # предыдущей строки — иначе однострочная директива дала
                # бы диапазон в две строки.
                end = max(start, field_value.end_mark.line)
                key_spans[(name, str(field_key.value))] = (start, end)
    return service_lines, key_spans


def _guard_size(text: str) -> None:
    if len(text.encode("utf-8", "ignore")) > MAX_FILE_BYTES:
        raise ValueError(
            f"файл больше {MAX_FILE_BYTES // (1024 * 1024)} МиБ — разбор пропущен "
            "(compose такого размера почти наверняка не конфигурация)"
        )


def _guard_schema(data: dict[str, Any]) -> None:
    if not data:
        return
    if any(key in TOP_LEVEL_KEYS or str(key).startswith("x-") for key in data):
        return
    raise ValueError(
        "нет ни одного ключа верхнего уровня современного compose "
        f"({', '.join(sorted(TOP_LEVEL_KEYS - {'x-'}))}) — похоже на формат "
        "docker-compose v1, который не поддерживается"
    )


def parse_compose(path: Path) -> ComposeFile:
    """Разбирает docker-compose.yml в ComposeFile (dict + номера строк)."""
    text = path.read_text(encoding="utf-8")
    _guard_size(text)

    data = yaml.safe_load(text)
    mapping = data if isinstance(data, dict) else {}
    _guard_schema(mapping)

    compose = ComposeFile(mapping)
    compose.service_lines, compose.key_spans = _line_marks(text)
    return compose
