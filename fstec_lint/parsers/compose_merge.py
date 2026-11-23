"""Bounded, local-only subset of ordered Compose overlays.

Only disjoint fields and declared scalar replacement are implemented. Refusing
ambiguous combines is deliberate: a partial result is safer than a wrong merge.
Docker specification: https://docs.docker.com/reference/compose-file/merge/
"""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .base import BoundedReader, SourceLine
from .compose import MAX_FILE_BYTES, ComposeFile, ComposeMergeError, _parse_compose_text

MAX_OVERLAY_FILES = 8
_TOP_MAPS = frozenset({"configs", "models", "networks", "secrets", "volumes"})
_TOP_SCALARS = frozenset({"name", "version"})
_SERVICE_SCALARS = frozenset(
    {
        "container_name",
        "cpus",
        "hostname",
        "image",
        "init",
        "ipc",
        "mem_limit",
        "network_mode",
        "pid",
        "privileged",
        "read_only",
        "restart",
        "tty",
        "use_api_socket",
        "user",
        "userns_mode",
        "uts",
        "working_dir",
    }
)


class MergedComposeFile(ComposeFile):
    """Compose data whose observed fields carry the supplying file."""

    def __init__(self, source_paths: tuple[Path, ...]) -> None:
        super().__init__()
        self.source_paths = source_paths
        self._order = {str(path): i for i, path in enumerate(source_paths)}
        self._service_headers: dict[tuple[str, str], int] = {}
        self._first_headers: dict[str, SourceLine] = {}
        self._fields: dict[tuple[str, str], tuple[str, int, int]] = {}

    def remember(self, layer: ComposeFile, path: Path, name: str, field: str | None = None) -> None:
        source = str(path)
        if field is None:
            if line := layer.service_lines.get(name):
                self._service_headers[(source, name)] = line
                self._first_headers.setdefault(name, SourceLine(line, source))
        else:
            span = layer.key_spans.get((name, field))
            if span is not None:
                self._fields[(name, field)] = (source, *span)

    def service_line(self, name: str) -> SourceLine | None:
        return self._first_headers.get(name)

    def key_line(self, service: str, *keys: str) -> SourceLine | None:
        spans = [self._fields[(service, key)] for key in keys if (service, key) in self._fields]
        if not spans:
            return self.service_line(service)
        path, start, _ = min(spans, key=lambda span: (self._order[span[0]], span[1]))
        return SourceLine(start, path)

    def suppression_lines(self, service: str, line: int | None) -> tuple[int, ...]:
        # Only lines belonging to the file attached to the finding can
        # suppress it. A line number from a different layer is unrelated.
        if not isinstance(line, SourceLine):
            return ()
        result = set()
        if header := self._service_headers.get((line.file, service)):
            result.add(header)
        for (name, _), (source, start, end) in self._fields.items():
            if name == service and source == line.file and start <= line <= end:
                result.update(range(start, end + 1))
        return tuple(sorted(result))


def _network_path(path: Path) -> bool:
    return path.as_posix().startswith(("//", "\\\\"))


def _local_path(path: Path, root: Path) -> Path:
    if _network_path(path) or (path.drive and not path.is_absolute()):
        raise ComposeMergeError("ожидался локальный абсолютный или относительный путь Compose")
    absolute = Path(os.path.abspath(path if path.is_absolute() else root / path))
    if not absolute.is_relative_to(root):
        raise ComposeMergeError("файл Compose находится за границей проверки")
    # Do not follow links/junctions before containment, including links to
    # remote shares. The actual read separately verifies the opened handle.
    node = root
    for component in absolute.relative_to(root).parts:
        node = node / component
        details = node.lstat()
        reparse = getattr(details, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        )
        if stat.S_ISLNK(details.st_mode) or reparse:
            raise ComposeMergeError("ссылки и точки повторного разбора Compose не поддерживаются")
    return absolute


def _plain_scalar_pair(before: object, after: object) -> bool:
    scalar = (str, int, float, bool)
    return isinstance(before, scalar) and isinstance(after, scalar)


def _named_map(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ComposeMergeError("ожидался словарь Compose с текстовыми ключами")
    return value


def _merge_services(layer: ComposeFile, result: MergedComposeFile, source: Path) -> None:
    existing = _named_map(result.setdefault("services", {}))
    for name, entry in _named_map(layer["services"]).items():
        service = _named_map(entry)
        result.remember(layer, source, name)
        selected = _named_map(existing.setdefault(name, {}))
        for key, value in service.items():
            if key in selected and (
                key not in _SERVICE_SCALARS or not _plain_scalar_pair(selected[key], value)
            ):
                raise ComposeMergeError(
                    "повтор поля сервиса выходит за границы поддерживаемого слияния Compose"
                )
            selected[key] = value
            result.remember(layer, source, name, key)


def _add_layer(layer: ComposeFile, result: MergedComposeFile, source: Path) -> None:
    for key, value in _named_map(layer).items():
        if key == "services":
            _merge_services(layer, result, source)
        elif key in _TOP_MAPS:
            existing = _named_map(result.setdefault(key, {}))
            incoming = _named_map(value)
            if existing.keys() & incoming.keys():
                raise ComposeMergeError("повтор ресурса верхнего уровня Compose не поддерживается")
            existing.update(incoming)
        elif key not in result or (key in _TOP_SCALARS and _plain_scalar_pair(result[key], value)):
            result[key] = value
        else:
            raise ComposeMergeError("повтор ключа Compose верхнего уровня не поддерживается")


def parse_compose_files(paths: Sequence[Path], scan_root: Path) -> ComposeFile:
    """Merge the explicitly ordered subset without interpolation or external files."""
    if not 1 <= len(paths) <= MAX_OVERLAY_FILES:
        raise ComposeMergeError(f"ожидалось 1–{MAX_OVERLAY_FILES} файлов Compose")
    if _network_path(scan_root):
        raise ComposeMergeError("ожидался локальный корень Compose")
    boundary = scan_root.resolve(strict=True)
    if _network_path(boundary):
        raise ComposeMergeError("ожидался локальный корень Compose")
    local = tuple(_local_path(path, boundary) for path in paths)
    if len(set(local)) != len(local):
        raise ComposeMergeError("файлы наложения Compose должны быть различными")
    reader = BoundedReader(boundary, max_bytes=MAX_FILE_BYTES)
    merged = MergedComposeFile(local)
    for path in local:
        _add_layer(_parse_compose_text(reader.read(path), overlay=True), merged, path)
    return merged
