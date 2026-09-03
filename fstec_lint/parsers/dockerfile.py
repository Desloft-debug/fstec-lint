from __future__ import annotations

import re
from pathlib import Path

_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def parse_dockerfile(path: Path) -> list[dict]:
    """Разбирает Dockerfile в список инструкций {instruction, args, line}.

    instruction — директива в верхнем регистре (FROM, RUN, USER, ...),
    line — номер строки, с которой началась инструкция (для
    многострочных инструкций с '\\' — первая строка).

    Тело heredoc (RUN <<EOF ... EOF) прикрепляется к args через перевод
    строки, а не разбирается как отдельные инструкции: иначе 'apt-get' из
    тела становится «директивой APT-GET», а USER внутри heredoc —
    несуществующим переключением пользователя.
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
            buffer = buffer[:-1].rstrip() + " " + lines[index].strip()
            index += 1

        tags = [match.group(2) for match in _HEREDOC_RE.finditer(buffer)]
        body: list[str] = []
        for tag in tags:
            while index < len(lines):
                raw = lines[index]
                index += 1
                if raw.strip() == tag:
                    break
                body.append(raw.strip())

        parts = buffer.split(None, 1)
        instruction = parts[0].upper()
        args = parts[1].strip() if len(parts) > 1 else ""
        if body:
            args = "\n".join([args, *body])
        instructions.append({"instruction": instruction, "args": args, "line": start_line})

    return instructions
