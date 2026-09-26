"""Конфигурация nginx: дерево директив с номерами строк и include."""

from __future__ import annotations

import glob
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .base import SourceLine, include_pattern

MAX_INCLUDE_DEPTH = 16


@dataclass
class Directive:
    name: str
    args: list[str]
    line: int
    block: list[Directive] | None = None


@dataclass
class NginxConfig:
    directives: list[Directive] = field(default_factory=list)

    def walk(
        self, items: list[Directive] | None = None, parents: tuple[str, ...] = ()
    ) -> Iterator[tuple[Directive, tuple[str, ...]]]:
        """(директива, цепочка контекстов) по всему дереву."""
        for item in self.directives if items is None else items:
            yield item, parents
            if item.block is not None:
                yield from self.walk(item.block, (*parents, item.name))


def _tokens(text: str) -> Iterator[tuple[str, int]]:
    """(токен, строка): слова, строки в кавычках, ';', '{', '}'."""
    i, line, n = 0, 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch.isspace():
            i += 1
        elif ch == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif ch in ";{}":
            yield ch, line
            i += 1
        elif ch in "\"'":
            quote, start_line, j = ch, line, i + 1
            buf = []
            while j < n and text[j] != quote:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            yield "".join(buf), start_line
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in ";{}":
                j += 1
            yield text[i:j], line
            i = j


def parse_nginx(path: Path) -> NginxConfig:
    config = NginxConfig()
    config.directives = _parse_file(path, path.parent, path, (path,))
    return config


def _parse_file(path: Path, base: Path, main: Path, stack: tuple[Path, ...]) -> list[Directive]:
    text = path.read_text(encoding="utf-8")
    included = path != main
    tokens = list(_tokens(text))
    pos = 0

    def mark(line: int) -> int:
        return SourceLine(line, str(path)) if included else line

    def block() -> list[Directive]:
        nonlocal pos
        items: list[Directive] = []
        words: list[tuple[str, int]] = []
        while pos < len(tokens):
            tok, line = tokens[pos]
            pos += 1
            if tok == ";":
                if words:
                    name, first = words[0]
                    args = [w for w, _ in words[1:]]
                    if name == "include" and args:
                        items.extend(_include(args[0], base, main, stack))
                    else:
                        items.append(Directive(name, args, mark(first)))
                words = []
            elif tok == "{":
                name, first = words[0] if words else ("", line)
                args = [w for w, _ in words[1:]]
                items.append(Directive(name, args, mark(first), block()))
                words = []
            elif tok == "}":
                return items
            else:
                words.append((tok, line))
        return items

    return block()


def _include(value: str, base: Path, main: Path, stack: tuple[Path, ...]) -> list[Directive]:
    pattern = include_pattern(value, base, "/etc/nginx")
    files = [Path(m) for m in sorted(glob.glob(pattern))] if pattern else []
    result: list[Directive] = []
    for file in (f for f in files if f.is_file()):
        if len(stack) >= MAX_INCLUDE_DEPTH:
            raise ValueError(f"include вложены глубже {MAX_INCLUDE_DEPTH} уровней")
        if file.resolve() in {p.resolve() for p in stack}:
            raise ValueError(f"циклический include: {file}")
        result.extend(_parse_file(file, base, main, (*stack, file)))
    return result
