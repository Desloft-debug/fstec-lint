"""Конфигурация nginx: дерево директив с номерами строк и include."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .base import BoundedReader, SourceLine

MAX_INCLUDE_DEPTH = 16


class _Quoted(str):
    """A quoted token is never nginx punctuation."""


@dataclass
class Directive:
    name: str
    args: list[str]
    line: int
    block: list[Directive] | None = None


@dataclass
class NginxConfig:
    directives: list[Directive] = field(default_factory=list)
    comment_offsets: dict[str, dict[int, int]] = field(default_factory=dict)

    def walk(
        self, items: list[Directive] | None = None, parents: tuple[str, ...] = ()
    ) -> Iterator[tuple[Directive, tuple[str, ...]]]:
        """(директива, цепочка контекстов) по всему дереву."""
        for item in self.directives if items is None else items:
            yield item, parents
            if item.block is not None:
                yield from self.walk(item.block, (*parents, item.name))


def _tokens(text: str, comments: dict[int, int]) -> Iterator[tuple[str, int]]:
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
            comments[line] = i - (text.rfind("\n", 0, i) + 1)
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
                    if text[j + 1] == "\n":
                        line += 1
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ValueError("unterminated quoted string")
            yield _Quoted("".join(buf)), start_line
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in ";{}":
                j += 1
            yield text[i:j], line
            i = j


def parse_nginx(path: Path, scan_root: Path | None = None) -> NginxConfig:
    config = NginxConfig()
    reader = BoundedReader(scan_root or path.parent)
    config.directives = _parse_file(path, path.parent.resolve(), reader, (), config.comment_offsets)
    return config


def _parse_file(
    path: Path,
    base: Path,
    reader: BoundedReader,
    stack: tuple[Path, ...],
    comments: dict[str, dict[int, int]],
) -> list[Directive]:
    path = reader.checked(path)
    text = reader.read(path, stack)
    stack = (*stack, path)
    tokens: list[tuple[str, int]] = []
    offsets: dict[int, int] = {}
    comments[str(path)] = offsets
    for token in _tokens(text, offsets):
        if len(tokens) >= 100000:
            raise ValueError("nginx token limit exceeded")
        tokens.append(token)
    pos = 0

    def mark(line: int) -> int:
        return SourceLine(line, str(path))

    def block(depth: int = 0) -> list[Directive]:
        nonlocal pos
        if depth > 64:
            raise ValueError("nginx nesting limit exceeded")
        items: list[Directive] = []
        words: list[tuple[str, int]] = []
        while pos < len(tokens):
            tok, line = tokens[pos]
            pos += 1
            if tok == ";" and not isinstance(tok, _Quoted):
                if words:
                    name, first = words[0]
                    args = [w for w, _ in words[1:]]
                    if name == "include" and args:
                        items.extend(_include(args[0], base, reader, stack, comments))
                    else:
                        items.append(Directive(name, args, mark(first)))
                words = []
            elif tok == "{" and not isinstance(tok, _Quoted):
                name, first = words[0] if words else ("", line)
                args = [w for w, _ in words[1:]]
                items.append(Directive(name, args, mark(first), block(depth + 1)))
                words = []
            elif tok == "}" and not isinstance(tok, _Quoted):
                if depth == 0 or words:
                    raise ValueError("invalid nginx block")
                return items
            else:
                words.append((tok, line))
        if depth or words:
            raise ValueError("incomplete nginx directive")
        return items

    return block()


def _include(
    value: str,
    base: Path,
    reader: BoundedReader,
    stack: tuple[Path, ...],
    comments: dict[str, dict[int, int]],
) -> list[Directive]:
    result: list[Directive] = []
    for file in reader.expand(value, base):
        result.extend(_parse_file(file, base, reader, stack, comments))
    return result
