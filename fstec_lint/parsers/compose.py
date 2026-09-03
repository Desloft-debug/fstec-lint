from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ComposeFile(dict[str, Any]):
    """Разобранный compose-файл, помнящий строку объявления каждого сервиса.

    Номера строк берутся из узлов YAML (yaml.compose), а не из повторного
    разбора текста регуляркой, поэтому совпадают с реальным файлом при
    любых отступах и якорях.
    """

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        super().__init__(data or {})
        self.service_lines: dict[str, int] = {}

    def service_line(self, name: str) -> int | None:
        return self.service_lines.get(name)


def _service_lines(text: str) -> dict[str, int]:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return {}
    if not isinstance(root, yaml.MappingNode):
        return {}
    for key_node, value_node in root.value:
        if key_node.value != "services" or not isinstance(value_node, yaml.MappingNode):
            continue
        return {
            str(service_key.value): service_key.start_mark.line + 1
            for service_key, _ in value_node.value
        }
    return {}


def parse_compose(path: Path) -> ComposeFile:
    """Разбирает docker-compose.yml в ComposeFile (dict + номера строк сервисов)."""
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    compose = ComposeFile(data if isinstance(data, dict) else {})
    compose.service_lines = _service_lines(text)
    return compose
