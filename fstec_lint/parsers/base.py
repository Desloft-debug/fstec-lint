"""Общие структуры для парсеров конфигов."""

from __future__ import annotations

import fnmatch
import os
import stat
import sys
from pathlib import Path


def _opened_path(fd: int) -> Path:
    """Identify the opened object before reading, or fail closed."""
    if sys.platform == "win32":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        get_name = ctypes.windll.kernel32.GetFinalPathNameByHandleW
        get_name.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_name.restype = wintypes.DWORD
        handle = msvcrt.get_osfhandle(fd)
        length = get_name(handle, None, 0, 0)
        if not length or length > 32767:
            raise ValueError("cannot validate opened configuration")
        buf = ctypes.create_unicode_buffer(length + 1)
        written = get_name(handle, buf, len(buf), 0)
        if not written or written >= len(buf):
            raise ValueError("cannot validate opened configuration")
        name = buf.value
        if name.startswith("\\\\?\\UNC\\"):
            name = "\\\\" + name[8:]
        elif name.startswith("\\\\?\\"):
            name = name[4:]
        return Path(name)
    link = Path(f"/proc/self/fd/{fd}")
    try:
        name = os.readlink(link)
    except OSError:
        raise ValueError("cannot validate opened configuration") from None
    if not name.startswith("/") or name.endswith(" (deleted)"):
        raise ValueError("cannot validate opened configuration")
    return Path(name)


def read_regular_bytes(path: Path, limit: int, *, root: Path | None = None) -> bytes:
    """Read at most limit bytes, optionally confined to a pre-resolved root."""
    if limit < 0:
        raise ValueError("negative read limit")
    if root is not None:
        path = path.resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError("file outside scan root")
    # Reject known special files before opening, then recheck the opened object.
    # O_NONBLOCK prevents a replacement FIFO from blocking before the recheck.
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("input is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if root is not None:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("input is not a regular file")
        if root is not None and not _opened_path(fd).is_relative_to(root):
            raise ValueError("opened file outside scan root")
        with os.fdopen(fd, "rb", closefd=False) as source:
            return source.read(limit)
    finally:
        os.close(fd)


class SourceLine(int):
    """Line number carrying the actual source file for integration by the engine."""

    file: str

    def __new__(cls, value: int, file: str) -> SourceLine:
        result = super().__new__(cls, value)
        result.file = file
        return result


class BoundedReader:
    """Bound reads to root, including validation of the opened handle."""

    def __init__(self, root: Path, *, max_bytes: int = 8 * 1024 * 1024) -> None:
        if max_bytes < 0:
            raise ValueError("negative read limit")
        self.root = root.resolve(strict=True)
        self.max_bytes = max_bytes
        self.files = 0
        self.size = 0
        self.work = 0

    def checked(self, path: Path) -> Path:
        resolved = path.resolve()
        if not resolved.is_relative_to(self.root):
            raise ValueError("include outside scan root")
        return resolved

    def local_include(self, path: Path) -> Path:
        """Validate a local fragment without following links or checking external paths."""
        if path.as_posix().startswith(("//", chr(92) * 2)) or (
            path.anchor and not path.is_absolute()
        ):
            raise ValueError("non-local include")
        absolute = path if path.is_absolute() else self.root / path
        if not absolute.is_relative_to(self.root):
            raise ValueError("include outside scan root")
        parts = absolute.relative_to(self.root).parts
        # Reject escapes syntactically even when an optional path is absent.
        depth = 0
        for component in parts:
            depth += -1 if component == ".." else 1
            if depth < 0:
                raise ValueError("include outside scan root")
        node = self.root
        for index, component in enumerate(parts):
            if component == "..":
                node = node.parent
                continue
            node = node / component
            info = node.lstat()
            reparse = getattr(info, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
            )
            if stat.S_ISLNK(info.st_mode) or reparse:
                raise ValueError("include link is not supported")
            if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                raise ValueError("include parent is not a directory")
        return node

    def read(self, path: Path, stack: tuple[Path, ...] = ()) -> str:
        resolved = self.checked(path)
        if resolved in stack:
            raise ValueError("include cycle")
        if len(stack) >= 16 or self.files >= 256:
            raise ValueError("include resource limit exceeded")
        self.files += 1
        raw = read_regular_bytes(resolved, self.max_bytes - self.size + 1, root=self.root)
        self.size += len(raw)
        if self.size > self.max_bytes:
            raise ValueError("include resource limit exceeded")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "invalid configuration encoding") from None

    def expand(self, pattern: str, base: Path) -> list[Path]:
        path = Path(pattern)
        path = path if path.is_absolute() else base / path
        # Resolve the non-wildcard prefix before any directory enumeration.
        path = Path(os.path.abspath(path))
        if not path.is_relative_to(self.root):
            raise ValueError("include outside scan root")
        parts = path.relative_to(self.root).parts
        pending = [self.root]
        wildcard = False
        for part in parts:
            magic = any(c in part for c in "*?[")
            wildcard |= magic
            next_paths: list[Path] = []
            for parent in pending:
                parent = self.checked(parent)
                if magic:
                    if not parent.is_dir():
                        continue
                    if self.work >= 16384:
                        raise ValueError("include expansion limit exceeded")
                    with os.scandir(parent) as entries:
                        for entry in entries:
                            self.work += 1
                            if self.work > 16384:
                                raise ValueError("include expansion limit exceeded")
                            if fnmatch.fnmatchcase(entry.name, part):
                                next_paths.append(self.checked(Path(entry.path)))
                else:
                    next_paths.append(self.checked(parent / part))
            pending = next_paths
        files = []
        for candidate in pending:
            if candidate.is_file():
                files.append(candidate)
            elif candidate.exists() or not wildcard:
                raise ValueError("include is not a regular file")
        return sorted(files, key=lambda p: str(p))

    def postgresql_include_dir(self, directory: Path, *, no_links: bool = False) -> list[Path]:
        """Order by directory entry names, before resolving their targets."""
        directory = self.local_include(directory) if no_links else self.checked(directory)
        if not directory.is_dir():
            raise ValueError("include directory missing")
        files: list[Path] = []
        with os.scandir(directory) as entries:
            for entry in entries:
                self.work += 1
                if self.work > 16384:
                    raise ValueError("include expansion limit exceeded")
                if entry.name.startswith(".") or not entry.name.endswith(".conf"):
                    continue
                if entry.is_dir(follow_symlinks=not no_links):
                    continue
                candidate = Path(entry.path)
                if no_links:
                    # Validate each fragment during parsing, so one rejected
                    # entry does not hide valid siblings.
                    files.append(candidate)
                    continue
                resolved = self.checked(candidate)
                if not resolved.is_file():
                    raise ValueError("include is not a regular file")
                files.append(candidate)
        return sorted(files, key=lambda p: p.name.encode("utf-8"))


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
