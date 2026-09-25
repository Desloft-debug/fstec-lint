from __future__ import annotations

import glob
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .base import ConfigMap, SourceLine

# Как SERVCONF_MAX_DEPTH в OpenSSH.
MAX_INCLUDE_DEPTH = 16
# Каталог, относительно которого sshd разрешает относительные пути Include.
SSHD_DIR = PurePosixPath("/etc/ssh")


@dataclass(frozen=True)
class MatchBlock:
    """Условный блок sshd_config: Match Address 10.0.0.0/8 и его директивы."""

    criteria: str
    line: int
    settings: ConfigMap


class SshdConfig(ConfigMap):
    """Глобальные директивы sshd_config и Match-блоки."""

    def __init__(self) -> None:
        super().__init__()
        self.matches: list[MatchBlock] = []


def _include_pattern(value: str, base: Path) -> str | None:
    """Путь Include в проверяемом дереве.

    Относительный путь sshd берёт от /etc/ssh, здесь — от каталога
    основного файла. Абсолютный путь используется как есть, если лежит
    внутри этого каталога; путь под /etc/ssh переносится в него. Прочие
    абсолютные пути указывают на файлы чужой системы и не читаются.
    """
    path = PurePosixPath(value)
    if not path.is_absolute():
        return str(base / path)
    try:
        PurePosixPath(value).relative_to(base.resolve().as_posix())
        return value
    except ValueError:
        pass
    try:
        return str(base / path.relative_to(SSHD_DIR))
    except ValueError:
        return None


def _parse_file(
    path: Path,
    config: SshdConfig,
    current: ConfigMap,
    base: Path,
    main: Path,
    stack: tuple[Path, ...],
) -> None:
    """Читает один файл в config.

    Match в подключённом файле действует до конца этого файла, как в sshd:
    после возврата из Include вызывающий продолжает со своей секцией.
    """
    included = path != main

    def mark(lineno: int) -> int:
        return SourceLine(lineno, str(path)) if included else lineno

    with open(path, encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            if key == "match":
                criteria = parts[1].strip() if len(parts) > 1 else ""
                block = MatchBlock(criteria=criteria, line=mark(lineno), settings=ConfigMap())
                config.matches.append(block)
                current = block.settings
                continue
            if len(parts) < 2:
                continue
            if key == "include":
                for value in parts[1].split():
                    _include(value, config, current, base, main, stack)
                continue
            if key not in current:
                current.set(key, parts[1].strip(), mark(lineno))


def _include(
    value: str,
    config: SshdConfig,
    current: ConfigMap,
    base: Path,
    main: Path,
    stack: tuple[Path, ...],
) -> None:
    pattern = _include_pattern(value, base)
    matches = sorted(glob.glob(pattern)) if pattern else []
    files = [Path(m) for m in matches if Path(m).is_file()]
    if not files:
        return  # как и sshd, пустой glob не считается ошибкой
    if len(stack) >= MAX_INCLUDE_DEPTH:
        raise ValueError(f"Include вложены глубже {MAX_INCLUDE_DEPTH} уровней")
    for file in files:
        if file.resolve() in {p.resolve() for p in stack}:
            raise ValueError(f"циклический Include: {file}")
        _parse_file(file, config, current, base, main, (*stack, file))


def parse_sshd_config(path: Path) -> SshdConfig:
    """Разбирает sshd_config вместе с Include.

    При повторе директивы действует первое значение, как в sshd, в том
    числе если оно пришло из подключённого файла.
    """
    config = SshdConfig()
    _parse_file(path, config, config, path.parent, path, (path,))
    return config
