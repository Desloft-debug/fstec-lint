from __future__ import annotations

import re
from pathlib import Path

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


def parse_dockerfile(path: Path) -> list[dict]:
    """Разбирает Dockerfile в список {instruction, args, line}.

    Тело heredoc приклеивается к args, а не разбирается как отдельные
    инструкции: иначе 'apt-get' из тела станет директивой APT-GET, а USER
    внутри heredoc — несуществующим переключением пользователя.
    """
    instructions: list[dict] = []
    lines = path.read_text(encoding="utf-8").splitlines()

    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        index += 1
        if not stripped or stripped.startswith("#"):
            continue

        start_line = index
        buffer = stripped
        while buffer.endswith("\\") and index < len(lines):
            following = lines[index].strip()
            index += 1
            # Комментарий внутри продолжения Docker отбрасывает, а сама
            # инструкция продолжается дальше. Приклеивать его к команде
            # нельзя: остаток строки уходил в отдельную «инструкцию» и
            # RUN терял хвост вместе с проверками по нему.
            if following.startswith("#"):
                continue
            buffer = buffer[:-1].rstrip() + " " + following

        parts = buffer.split(None, 1)
        instruction = parts[0].upper()
        args = parts[1].strip() if len(parts) > 1 else ""

        if instruction in HEREDOC_INSTRUCTIONS:
            body, index = _heredoc_body(lines, index, buffer)
            if body:
                args = "\n".join([args, *body])

        instructions.append({"instruction": instruction, "args": args, "line": start_line})

    return instructions
