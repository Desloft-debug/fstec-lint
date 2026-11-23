from pathlib import Path

import pytest

from fstec_lint.parsers.base import BoundedReader, read_regular_bytes
from fstec_lint.parsers.systemd import parse_systemd_unit


def test_regular_reader_honors_byte_cap(tmp_path: Path) -> None:
    source = tmp_path / "input.conf"
    source.write_bytes(b"one\ntwo\n")
    assert read_regular_bytes(source, 4, root=tmp_path.resolve()) == b"one\n"
    assert BoundedReader(tmp_path, max_bytes=8).read(source) == "one\ntwo\n"
    with pytest.raises(ValueError, match="resource limit"):
        BoundedReader(tmp_path, max_bytes=7).read(source)


def test_regular_reader_requires_file(tmp_path: Path) -> None:
    directory = tmp_path / "directory.conf"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        read_regular_bytes(directory, 16)


def test_systemd_bounded_reader_preserves_continuation_and_line(tmp_path: Path) -> None:
    units = tmp_path / "units"
    units.mkdir()
    service = units / "demo.service"
    service.write_text(
        "[Service]\nExecStart=/bin/echo \\\n# a comment\n   hello\n",
        encoding="utf-8",
    )
    result = parse_systemd_unit(service, scan_root=tmp_path)
    assert result["Service"]["ExecStart"] == "/bin/echo hello"
    assert result["Service"].line("ExecStart") == 2
