"""Write only complete private reports; never write through a destination link."""

from __future__ import annotations

import os
import stat
import tempfile
import unicodedata
from pathlib import Path


def visible(value: object) -> str:
    return "".join(
        (f"\\x{ord(char):02x}" if ord(char) <= 0xFF else f"\\u{ord(char):04x}")
        if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        else char
        for char in str(value)
    )


def write_report(destination: Path, data: bytes, *, overwrite: bool = True) -> None:
    """Replace an ordinary report atomically in a caller-trusted directory."""
    parent = destination.parent.resolve(strict=True)
    path = parent / destination.name
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        pass
    else:
        if not overwrite:
            raise FileExistsError("файл отчёта уже существует")
        if not stat.S_ISREG(mode):
            raise ValueError("назначение отчёта должно быть обычным файлом, не ссылкой")
    fd, name = tempfile.mkstemp(prefix=".fstec-lint-", dir=parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Never open the destination for writing. If switched after lstat,
        # replace the directory entry itself, not its target.
        if overwrite:
            os.replace(temp, path)
        elif os.name == "nt":
            os.rename(temp, path)  # Windows rename refuses an existing destination.
        else:
            os.link(temp, path)  # Exclusive publication of a complete report.
    finally:
        temp.unlink(missing_ok=True)
