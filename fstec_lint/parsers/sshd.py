from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .base import ConfigMap


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


def parse_sshd_config(path: Path) -> SshdConfig:
    """Разбирает sshd_config: глобальные директивы + список Match-блоков.

    Ключи приводятся к нижнему регистру. При повторе директивы в пределах
    одной секции побеждает первое вхождение — так же ведёт себя сам sshd.
    """
    config = SshdConfig()
    current: ConfigMap = config

    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            if key == "match":
                criteria = parts[1].strip() if len(parts) > 1 else ""
                block = MatchBlock(criteria=criteria, line=lineno, settings=ConfigMap())
                config.matches.append(block)
                current = block.settings
                continue
            if len(parts) < 2:
                continue
            if key not in current:
                current.set(key, parts[1].strip(), lineno)
    return config
