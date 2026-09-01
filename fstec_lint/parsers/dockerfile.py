from __future__ import annotations

from pathlib import Path


def parse_dockerfile(path: Path) -> list[dict]:
    """Разбирает Dockerfile в список инструкций {instruction, args, line}.

    instruction — директива в верхнем регистре (FROM, RUN, USER, ...),
    line — номер строки, с которой началась инструкция (для
    многострочных инструкций с '\\' — первая строка).
    """
    instructions: list[dict] = []
    buffer = ""
    start_line: int | None = None

    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if start_line is None:
                start_line = lineno
            if stripped.endswith("\\"):
                buffer += stripped[:-1] + " "
                continue
            buffer += stripped
            parts = buffer.split(None, 1)
            instruction = parts[0].upper()
            args = parts[1].strip() if len(parts) > 1 else ""
            instructions.append({"instruction": instruction, "args": args, "line": start_line})
            buffer = ""
            start_line = None

    return instructions
