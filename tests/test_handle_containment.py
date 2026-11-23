import pytest

from fstec_lint.parsers import base


def test_opened_file_validation_precedes_stream_creation(tmp_path, monkeypatch):
    target = tmp_path / "fixture.conf"
    target.write_text("ssl=on\n", encoding="utf-8")

    def unexpected_stream(*args, **kwargs):
        pytest.fail("buffered stream created before validating the descriptor")

    monkeypatch.setattr(base, "_opened_path", lambda fd: tmp_path.parent / "not-opened.conf")
    monkeypatch.setattr(base.os, "fdopen", unexpected_stream)
    with pytest.raises(ValueError, match="opened file outside"):
        base.BoundedReader(tmp_path).read(target)
