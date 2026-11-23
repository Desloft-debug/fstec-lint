"""Bounded, local-only subset of ordered Compose overlays.

Only declared replacement and selected field-specific combinations are
implemented. A partial result is safer than a wrong merge.
Docker specification: https://docs.docker.com/reference/compose-file/merge/
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Sequence
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from .base import BoundedReader, SourceLine
from .compose import MAX_FILE_BYTES, ComposeFile, ComposeMergeError, _parse_compose_text

MAX_OVERLAY_FILES = 8
_TOP_MAPS = frozenset({"configs", "models", "networks", "secrets", "volumes"})
_TOP_SCALARS = frozenset({"name", "version"})
_PORT_NUMBER = re.compile(r"[1-9][0-9]{0,4}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PORT_KEYS = frozenset(
    {"target", "published", "host_ip", "protocol", "mode", "name", "app_protocol"}
)
_HEALTH_KEYS = frozenset(
    {"disable", "test", "interval", "timeout", "retries", "start_period", "start_interval"}
)
_FieldSpan = tuple[str, int, int]
_EntryKey = str | int
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
        self._fields: dict[tuple[str, str], _FieldSpan] = {}
        self._entry_fields: dict[tuple[str, str], dict[_EntryKey, _FieldSpan]] = {}
        self._source_spans: dict[tuple[str, str], set[tuple[int, int]]] = {}

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
                self._source_spans.setdefault((source, name), set()).add(span)

    def service_line(self, name: str) -> SourceLine | None:
        return self._first_headers.get(name)

    def key_line(self, service: str, *keys: str) -> SourceLine | None:
        spans = [self._fields[(service, key)] for key in keys if (service, key) in self._fields]
        if not spans:
            return self.service_line(service)
        path, start, _ = min(spans, key=lambda span: (self._order[span[0]], span[1]))
        return SourceLine(start, path)

    def entry_line(self, service: str, field: str, entry: _EntryKey) -> SourceLine | None:
        span = self._entry_fields.get((service, field), {}).get(entry)
        return SourceLine(span[1], span[0]) if span else self.key_line(service, field)

    def remember_combined(
        self,
        layer: ComposeFile,
        path: Path,
        service: str,
        field: str,
        origins: dict[_EntryKey, tuple[bool, _EntryKey]],
    ) -> None:
        old = self._entry_fields.get((service, field), {})
        old_default = self._fields.get((service, field))
        new_span = layer.key_spans.get((service, field))
        new: _FieldSpan | None = (str(path), *new_span) if new_span is not None else None
        updated = {}
        for entry, (from_new, previous_key) in origins.items():
            span = new if from_new else old.get(previous_key, old_default)
            if span is not None:
                updated[entry] = span
        self._entry_fields[(service, field)] = updated

    def suppression_lines(self, service: str, line: int | None) -> tuple[int, ...]:
        # Only lines belonging to the file attached to the finding can
        # suppress it. A line number from a different layer is unrelated.
        if not isinstance(line, SourceLine):
            return ()
        result = set()
        if header := self._service_headers.get((line.file, service)):
            result.add(header)
        for start, end in self._source_spans.get((line.file, service), ()):
            if start <= line <= end:
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


def _literal_env(value: object) -> dict[str, Any]:
    if isinstance(value, list):
        entries: dict[str, Any] = {}
        for item in value:
            if not isinstance(item, str):
                raise ComposeMergeError("ожидалась запись окружения Compose")
            name, equal, literal = item.partition("=")
            if name in entries:
                raise ComposeMergeError("повтор переменной в одном слое Compose")
            entries[name] = literal if equal else None
    else:
        entries = _named_map(value)
    if any(
        _ENV_NAME.fullmatch(key) is None or type(item) not in (str, int, float, bool, type(None))
        for key, item in entries.items()
    ):
        raise ComposeMergeError("неподдерживаемый формат окружения Compose")
    return entries


def _health_map(value: object) -> dict[str, Any]:
    entries = _named_map(value)
    for key, item in entries.items():
        if key == "test":
            valid = isinstance(item, str) or (
                isinstance(item, list) and all(isinstance(part, str) for part in item)
            )
        elif key == "disable":
            valid = isinstance(item, (str, bool))
        elif key == "retries":
            valid = type(item) is int
        else:
            valid = key in _HEALTH_KEYS and isinstance(item, str)
        if not valid:
            raise ComposeMergeError("неподдерживаемый формат healthcheck Compose")
    return entries


def _number(value: object, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if type(value) in (int, str):
        number = str(value)
        if _PORT_NUMBER.fullmatch(number) and int(number) <= 65535:
            return number
    raise ComposeMergeError("диапазон или неоднозначный номер порта Compose")


def _port_key(entry: object) -> tuple[str, str, str, str]:
    if isinstance(entry, dict):
        if entry.keys() - _PORT_KEYS or any(
            type(value) not in (str, int) for value in entry.values()
        ):
            raise ComposeMergeError("неподдерживаемая форма порта Compose")
        host = entry.get("host_ip", "")
        protocol = entry.get("protocol", "tcp")
        target = entry.get("target")
        published = entry.get("published", "")
    elif type(entry) in (int, str):
        address, slash, protocol = str(entry).partition("/")
        if not slash:
            protocol = "tcp"
        host = ""
        if address.startswith("["):
            bracket, marker, address = address.partition("]:")
            if not marker:
                raise ComposeMergeError("неподдерживаемый адрес порта Compose")
            host = bracket[1:]
        fields = address.split(":")
        if len(fields) == 3 and not host:
            host, *fields = fields
        if len(fields) == 1 and not host:
            (target,) = fields
            published = ""
        elif len(fields) == 2:
            published, target = fields
        else:
            raise ComposeMergeError("неподдерживаемая форма порта Compose")
    else:
        raise ComposeMergeError("неподдерживаемая форма порта Compose")
    if not isinstance(host, str) or protocol not in ("tcp", "udp", "sctp"):
        raise ComposeMergeError("неподдерживаемый адрес или протокол порта Compose")
    if host:
        try:
            if "%" in host or str(ip_address(host)) != host:
                raise ValueError
        except ValueError:
            raise ComposeMergeError("неподдерживаемый адрес порта Compose") from None
    # A binding with no host and an explicit IPv4 wildcard can collide.
    # Treat different representations of that key as ambiguous, not separate.
    return host or "0.0.0.0", _number(target), _number(published, optional=True), protocol


def _merge_ports(
    before: object, after: object
) -> tuple[list[Any], dict[_EntryKey, tuple[bool, _EntryKey]]]:
    merged: list[Any] = []
    origins: dict[_EntryKey, tuple[bool, _EntryKey]] = {}
    known: dict[tuple[str, str, str, str], Any] = {}
    for from_new, layer in ((False, before), (True, after)):
        if not isinstance(layer, list):
            raise ComposeMergeError("ожидался список портов Compose")
        layer_keys = set()
        for index, item in enumerate(layer):
            key = _port_key(item)
            if key in layer_keys:
                raise ComposeMergeError("повтор порта в одном слое Compose")
            layer_keys.add(key)
            if key in known:
                if item != known[key] or type(item) is not type(known[key]):
                    raise ComposeMergeError("сложное переопределение порта Compose")
                continue
            known[key] = item
            origins[len(merged)] = (from_new, index)
            merged.append(item)
    return merged, origins


def _merge_field(
    field: str, before: object, after: Any
) -> tuple[Any, dict[_EntryKey, tuple[bool, _EntryKey]] | None]:
    if field in _SERVICE_SCALARS and _plain_scalar_pair(before, after):
        return after, None
    if field == "ports":
        return _merge_ports(before, after)
    if field in {"environment", "healthcheck"}:
        parser = _literal_env if field == "environment" else _health_map
        old, new = parser(before), parser(after)
        combined = {**old, **new}
        origins: dict[_EntryKey, tuple[bool, _EntryKey]] = {
            key: (key in new, key) for key in combined
        }
        return combined, origins
    raise ComposeMergeError(
        "повтор поля сервиса выходит за границы поддерживаемого слияния Compose"
    )


def _merge_services(layer: ComposeFile, result: MergedComposeFile, source: Path) -> None:
    existing = _named_map(result.setdefault("services", {}))
    for name, entry in _named_map(layer["services"]).items():
        service = _named_map(entry)
        result.remember(layer, source, name)
        selected = _named_map(existing.setdefault(name, {}))
        for key, value in service.items():
            if key in selected:
                value, origins = _merge_field(key, selected[key], value)
                if origins is not None:
                    result.remember_combined(layer, source, name, key, origins)
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
