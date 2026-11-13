from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from .base import BoundedReader, ConfigMap, SourceLine


@dataclass(frozen=True)
class MatchBlock:
    """Условный блок sshd_config: Match Address 10.0.0.0/8 и его директивы."""

    criteria: str
    line: int
    settings: ConfigMap


class SshdConfig(ConfigMap):
    """Глобальные директивы sshd_config плюс условные Match-блоки.

    Match-блоки лежат отдельно, потому что правила к ним применяются
    иначе: неуказанная директива внутри блока не «выключена», а
    унаследована из глобальной секции, и повторно её проверять нельзя.
    """

    def __init__(self) -> None:
        super().__init__()
        self.matches: list[MatchBlock] = []


def parse_sshd_config(path: Path, scan_root: Path | None = None) -> SshdConfig:
    """Разбирает sshd_config: глобальные директивы + список Match-блоков.

    Ключи приводятся к нижнему регистру. При повторе директивы в пределах
    одной секции побеждает первое вхождение — так же ведёт себя сам sshd.
    """
    config = SshdConfig()
    reader = BoundedReader(scan_root if scan_root is not None else path.parent)
    base = path.parent.resolve()

    def parse_file(file: Path, current: ConfigMap, stack: tuple[Path, ...]) -> None:
        resolved = reader.checked(file)
        text = reader.read(resolved, stack)
        stack = (*stack, resolved)
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            try:
                words = shlex.split(raw_line, comments=True, posix=True)
            except ValueError:
                raise ValueError("invalid sshd configuration syntax") from None
            if not words:
                continue
            key = words[0].lower()
            mark = SourceLine(lineno, str(resolved))
            if key == "match":
                criteria = " ".join(words[1:])
                block = MatchBlock(criteria=criteria, line=mark, settings=ConfigMap())
                config.matches.append(block)
                current = block.settings
                continue
            if len(words) < 2:
                raise ValueError("invalid sshd configuration syntax")
            if key == "maxauthtries" and (
                len(words) != 2 or not words[1].isascii() or not words[1].isdigit()
            ):
                raise ValueError("invalid sshd numeric value")
            if key == "include":
                for pattern in words[1:]:
                    for included in reader.expand(pattern, base):
                        parse_file(included, current, stack)
                continue
            if key not in current:
                current.set(key, " ".join(words[1:]), mark)

    parse_file(path, config, ())
    return config
