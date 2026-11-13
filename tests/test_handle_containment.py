from pathlib import Path

import pytest

from fstec_lint.engine import scan
from fstec_lint.parsers.base import BoundedReader


@pytest.mark.parametrize("surface", ["reader", "main"])
def test_opened_file_substitution_rejected_before_read(tmp_path, monkeypatch, surface):
    selected = tmp_path / "selected"
    selected.mkdir()
    target = selected / "postgresql.conf"
    target.write_text("ssl=off\n", encoding="utf-8")
    outside = tmp_path / "outside.conf"
    outside.write_text("ssl=on\n", encoding="utf-8")
    original_open = Path.open
    read_calls = []

    class Observed:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.file, name)

        def read(self, *args):
            read_calls.append(True)
            return self.file.read(*args)

    def substituted(path, *args, **kwargs):
        if path != target:
            return original_open(path, *args, **kwargs)
        return Observed(original_open(outside, *args, **kwargs))

    monkeypatch.setattr(Path, "open", substituted)
    if surface == "reader":
        with pytest.raises(ValueError):
            BoundedReader(selected).read(target)
    else:
        result = scan(target, select=["P005"])
        assert result.errors
    assert not read_calls
