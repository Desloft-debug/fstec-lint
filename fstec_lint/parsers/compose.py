from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .base import BoundedReader

# Файл с именем docker-compose.yml, где нет ни одного из этих ключей, —
# формат v1: сервисы лежат прямо в корне. Разбирать его как современный
# значит выдать «нарушений не найдено» на непроверенном файле.
TOP_LEVEL_KEYS = frozenset(
    {"services", "version", "volumes", "networks", "configs", "secrets", "include", "name", "x-"}
)

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 100_000
MAX_YAML_ALIASES = 1_024
MAX_MERGE_WORK = 65_536
MAX_YAML_EXPANDED_COST = 16 * 1024 * 1024


class _BoundedLoader(yaml.SafeLoader):
    """Bound the composer before it builds a YAML node graph."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0
        self._aliases = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            self._aliases += 1
            if self._aliases > MAX_YAML_ALIASES:
                raise ValueError("YAML resource limit exceeded")
        else:
            self._nodes += 1
            if self._nodes > MAX_YAML_NODES:
                raise ValueError("YAML resource limit exceeded")
        self._depth += 1
        try:
            if self._depth > MAX_YAML_DEPTH:
                raise ValueError("YAML resource limit exceeded")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _compose_tag(loader: _BoundedLoader, node: Any) -> Any:
    """Interpret a tag for one file; this does not merge Compose files."""
    if node.tag == "!reset":
        if isinstance(node, yaml.SequenceNode):
            return []
        if isinstance(node, yaml.MappingNode):
            return {}
        return None
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.ScalarNode):
        tag = loader.resolve(yaml.ScalarNode, node.value, (node.style is None, False))
        scalar = yaml.ScalarNode(tag, node.value, node.start_mark, node.end_mark, node.style)
        return loader.construct_object(scalar, deep=True)
    raise ValueError("invalid Compose tag")


_BoundedLoader.add_constructor("!reset", _compose_tag)
_BoundedLoader.add_constructor("!override", _compose_tag)


def _guard_graph(root: Any) -> None:
    """Bound expanded traversal and representation cost without expanding aliases.

    Each edge contributes the full cached cost of its target. Scalar cost is
    conservative for escaped Python representations; container overhead covers
    delimiters and separators. Height includes alias edges, not just syntax.
    """
    completed: dict[int, tuple[int, int]] = {}
    active: set[int] = set()

    def visit(node: Any, depth: int) -> tuple[int, int]:
        if depth > MAX_YAML_DEPTH:
            raise ValueError("YAML resource limit exceeded")
        ident = id(node)
        if ident in active:
            raise ValueError("YAML resource limit exceeded")
        if ident in completed:
            cost, height = completed[ident]
            if depth + height - 1 > MAX_YAML_DEPTH:
                raise ValueError("YAML resource limit exceeded")
            return cost, height
        active.add(ident)
        cost, height = 32, 1
        if isinstance(node, yaml.ScalarNode):
            cost += 12 * len(node.value)
            children: list[Any] = []
        elif isinstance(node, yaml.SequenceNode):
            children = node.value
        elif isinstance(node, yaml.MappingNode):
            children = []
            for key, value in node.value:
                if not isinstance(key, yaml.ScalarNode):
                    raise ValueError("invalid YAML mapping key")
                children.extend((key, value))
        else:
            raise ValueError("invalid YAML node")
        if cost > MAX_YAML_EXPANDED_COST:
            raise ValueError("YAML resource limit exceeded")
        for child in children:
            child_cost, child_height = visit(child, depth + 1)
            cost += child_cost
            height = max(height, child_height + 1)
            if cost > MAX_YAML_EXPANDED_COST:
                raise ValueError("YAML resource limit exceeded")
        active.remove(ident)
        completed[ident] = (cost, height)
        return cost, height

    if root is not None:
        visit(root, 1)


def _guard_merges(root: Any) -> None:
    """Budget PyYAML's flatten_mapping copies before constructing any objects."""
    nodes = [root]
    seen: set[int] = set()
    mappings: list[Any] = []
    while nodes:
        node = nodes.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            mappings.append(node)
            for key, value in node.value:
                nodes.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            nodes.extend(node.value)

    lengths: dict[int, int] = {}
    active: set[int] = set()
    work = 0

    def expanded(node: Any, depth: int) -> int:
        nonlocal work
        ident = id(node)
        if ident in active or depth > MAX_YAML_DEPTH:
            raise ValueError("YAML resource limit exceeded")
        if ident in lengths:
            return lengths[ident]
        active.add(ident)
        count = 0
        for key, value in node.value:
            if key.tag != "tag:yaml.org,2002:merge":
                count += 1
                continue
            targets = value.value if isinstance(value, yaml.SequenceNode) else [value]
            for target in targets:
                if not isinstance(target, yaml.MappingNode):
                    raise ValueError("Invalid YAML merge")
                pairs = expanded(target, depth + 1)
                count += pairs
                work += pairs
                if count > MAX_MERGE_WORK or work > MAX_MERGE_WORK:
                    raise ValueError("YAML resource limit exceeded")
        active.remove(ident)
        lengths[ident] = count
        return count

    for mapping in mappings:
        expanded(mapping, 1)


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
        """Строки, на которых комментарий гасит находку.

        Заголовок сервиса плюс все строки директивы — чтобы работал и
        комментарий у конкретного элемента списка.
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


def _line_marks(root: object) -> tuple[dict[str, int], dict[tuple[str, str], tuple[int, int]]]:
    service_lines: dict[str, int] = {}
    key_spans: dict[tuple[str, str], tuple[int, int]] = {}
    for key_node, value_node in _mapping(root):
        if key_node.value != "services":
            continue
        for service_key, service_value in _mapping(value_node):
            name = service_key.value
            service_lines[name] = service_key.start_mark.line + 1
            for field_key, field_value in _mapping(service_value):
                start = field_key.start_mark.line + 1
                # end_mark блочного узла указывает на начало следующей
                # строки, поэтому конец берётся как максимум из начала и
                # предыдущей строки — иначе однострочная директива дала
                # бы диапазон в две строки.
                end = max(start, field_value.end_mark.line)
                key_spans[(name, field_key.value)] = (start, end)
    return service_lines, key_spans


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


def parse_compose(path: Path, scan_root: Path | None = None) -> ComposeFile:
    """Разбирает docker-compose.yml в ComposeFile (dict + номера строк)."""
    text = BoundedReader(scan_root or path.parent, max_bytes=MAX_FILE_BYTES).read(path)

    try:
        loader = _BoundedLoader(text)
    except yaml.YAMLError:
        raise ValueError("invalid YAML") from None
    try:
        root = loader.get_single_node()
        _guard_graph(root)
        _guard_merges(root)
        lines, spans = _line_marks(root)
        data = loader.construct_document(root) if root is not None else None
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        safe_mark = (
            yaml.error.Mark("<yaml>", mark.index, mark.line, mark.column, None, 0)
            if mark is not None
            else None
        )
        raise type(exc)(None, None, "invalid YAML", safe_mark) from None
    except yaml.YAMLError:
        raise ValueError("invalid YAML") from None
    except Exception:  # noqa: BLE001 - constructors may include scalar values in exceptions
        raise ValueError("invalid YAML or YAML resource limit exceeded") from None
    finally:
        loader.dispose()
    mapping = data if isinstance(data, dict) else {}
    _guard_schema(mapping)
    services = mapping.get("services", {})
    if "include" in mapping or (
        isinstance(services, dict)
        and any(isinstance(service, dict) and "extends" in service for service in services.values())
    ):
        raise ValueError("unsupported Compose include or extends")

    compose = ComposeFile(mapping)
    compose.service_lines, compose.key_spans = lines, spans
    return compose
