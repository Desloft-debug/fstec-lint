from __future__ import annotations

import re
from pathlib import Path

from .base import BoundedReader

# Оператор heredoc, но не here-string '<<<': в 'grep x <<<"payload"'
# начала heredoc нет, а тег там всё равно вычитывался.
_HEREDOC_RE = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# Docker принимает heredoc только у этих инструкций.
HEREDOC_INSTRUCTIONS = frozenset({"RUN", "COPY", "ADD"})


def _heredoc_body(lines: list[str], index: int, buffer: str) -> tuple[list[str], int]:
    """Тело heredoc-ов инструкции и позиция за последним ограничителем.

    Ограничитель не встретился до конца файла — значит '<<' было частью
    команды ('echo "a << b"'), а не началом heredoc. Тогда возвращаем
    исходную позицию: иначе весь остаток файла уедет в аргументы одной
    инструкции вместе со всеми находками, которые в нём были.
    """
    body: list[str] = []
    cursor = index
    for match in _HEREDOC_RE.finditer(buffer):
        tag = match.group(2)
        closed = False
        while cursor < len(lines):
            raw = lines[cursor]
            cursor += 1
            if raw.strip() == tag:
                closed = True
                break
            body.append(raw.strip())
        if not closed:
            return [], index
    return body, cursor


def parse_dockerfile(path: Path, scan_root: Path | None = None) -> list[dict]:
    """Разбирает Dockerfile в список {instruction, args, line}.

    Тело heredoc приклеивается к args, а не разбирается как отдельные
    инструкции: иначе 'apt-get' из тела станет директивой APT-GET, а USER
    внутри heredoc — несуществующим переключением пользователя.
    """
    instructions: list[dict] = []
    lines = BoundedReader(scan_root or path.parent).read(path).splitlines()

    escape = "\\"
    directives_open = True
    seen_escape = False
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        index += 1
        if not stripped:
            directives_open = False
            continue
        if stripped.startswith("#"):
            if directives_open:
                directive = re.fullmatch(
                    r"#\s*(syntax|escape|check)\s*=\s*(.*?)\s*", stripped, re.IGNORECASE
                )
                if directive is None:
                    directives_open = False
                elif directive.group(1).lower() == "escape":
                    value = directive.group(2)
                    if seen_escape or value not in ("\\", "`"):
                        raise ValueError("invalid Dockerfile escape directive")
                    escape = value
                    seen_escape = True
            continue
        directives_open = False

        start_line = index
        # BuildKit strips leading whitespace only on the first physical line.
        # Continuation removes the escape and trailing spaces, but never inserts
        # a space or discards the next line's indentation (cu + rl means curl).
        continuation = re.compile(
            r"(?<!" + re.escape(escape) + r")" + re.escape(escape) + r"[ \t]*$"
        )
        buffer = lines[index - 1].lstrip()
        match = continuation.search(buffer)
        continued = match is not None
        if match is not None:
            buffer = buffer[: match.start()]
        while continued and index < len(lines):
            following = lines[index]
            index += 1
            if not following.strip() or following.lstrip().startswith("#"):
                continue
            match = continuation.search(following)
            continued = match is not None
            if match is not None:
                following = following[: match.start()]
            buffer += following

        parts = buffer.split(None, 1)
        instruction = parts[0].upper()
        args = parts[1].strip() if len(parts) > 1 else ""

        if instruction in HEREDOC_INSTRUCTIONS:
            body, index = _heredoc_body(lines, index, buffer)
            if body:
                args = "\n".join([args, *body])

        instructions.append({"instruction": instruction, "args": args, "line": start_line})

    return instructions
