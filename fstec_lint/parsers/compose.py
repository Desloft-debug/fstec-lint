from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Если ни одного из этих ключей нет — формат v1, сервисы в корне.
TOP_LEVEL_KEYS = frozenset(
    {"services", "version", "volumes", "networks", "configs", "secrets", "include", "name", "x-"}
)

# Файл читается в память целиком, поэтому размер ограничен.
MAX_FILE_BYTES = 8 * 1024 * 1024


class ComposeFile(dict[str, Any]):
    """Разобранный compose-файл со строками сервисов и их ключей.

    Строки берутся из узлов YAML (yaml.compose).
    """

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        super().__init__(data or {})
        self.service_lines: dict[str, int] = {}
        # (сервис, ключ) -> (первая и последняя строка директивы).
        self.key_spans: dict[tuple[str, str], tuple[int, int]] = {}
        self.volume_lines: dict[str, int] = {}

    def volume_line(self, name: str) -> int | None:
        return self.volume_lines.get(name)

    def service_line(self, name: str) -> int | None:
        return self.service_lines.get(name)

    def key_line(self, service: str, *keys: str) -> int | None:
        """Строка самого раннего из ключей сервиса, иначе строка сервиса."""
        starts = [
            span[0] for key in keys if (span := self.key_spans.get((service, key))) is not None
        ]
        return min(starts) if starts else self.service_lines.get(service)

    def suppression_lines(self, service: str, line: int | None) -> tuple[int, ...]:
        """Строки для подавления: заголовок сервиса и все строки директивы."""
        lines: set[int] = set()
        if (header := self.service_lines.get(service)) is not None:
            lines.add(header)
        if line is not None:
            for (name, _key), (start, end) in self.key_spans.items():
                if name == service and start <= line <= end:
                    lines.update(range(start, end + 1))
        return tuple(sorted(lines))


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader с тегами слияния Compose: !reset и !override."""


def _construct_reset(loader: yaml.SafeLoader, node: yaml.Node) -> None:
    # !reset возвращает поле к значению по умолчанию, то есть «не задано».
    return None


def _construct_override(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    # !override заменяет значение из базового файла вместо слияния;
    # для разбора одного файла это обычное значение.
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!reset", _construct_reset)
_ComposeLoader.add_constructor("!override", _construct_override)


def _mapping(node: object) -> list[tuple[Any, Any]]:
    return node.value if isinstance(node, yaml.MappingNode) else []


def _line_marks(
    text: str,
) -> tuple[dict[str, int], dict[tuple[str, str], tuple[int, int]], dict[str, int]]:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return {}, {}, {}

    service_lines: dict[str, int] = {}
    key_spans: dict[tuple[str, str], tuple[int, int]] = {}
    volume_lines: dict[str, int] = {}
    for key_node, value_node in _mapping(root):
        if key_node.value == "volumes":
            for volume_key, _ in _mapping(value_node):
                volume_lines[str(volume_key.value)] = volume_key.start_mark.line + 1
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
    return service_lines, key_spans, volume_lines


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

    data = yaml.load(text, Loader=_ComposeLoader)  # наследник SafeLoader
    mapping = data if isinstance(data, dict) else {}
    _guard_schema(mapping)

    compose = ComposeFile(mapping)
    compose.service_lines, compose.key_spans, compose.volume_lines = _line_marks(text)
    return compose
