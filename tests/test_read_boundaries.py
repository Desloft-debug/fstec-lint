"""Opened-object containment applies to every selected configuration format.

The explicit user contract forbids external-byte consumption. Substituting the
opened handle deterministically exercises the window after pathname validation;
safe refusal is allowed, reading first and reporting an error later is not.
"""

from pathlib import Path

import pytest

from fstec_lint.engine import scan


@pytest.mark.parametrize(
    "filename,body,rule",
    [
        ("compose.yaml", "services: {app: {privileged: true}}\n", "C002"),
        ("Dockerfile", "FROM alpine:3.20\nUSER root\n", "D001"),
    ],
)
def test_scan_rejects_external_opened_object_before_read(
    tmp_path, monkeypatch, filename, body, rule
):
    selected = tmp_path / "selected"
    selected.mkdir()
    target = selected / filename
    target.write_text(body, encoding="utf-8")
    outside = tmp_path / "outside.conf"
    outside.write_text(body, encoding="utf-8")
    real_open = Path.open
    attempts = []
    external_reads = []

    class ObservedFile:
        def __init__(self, source):
            self.source = source

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.source.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.source, name)

        def read(self, *args):
            result = self.source.read(*args)
            external_reads.append(len(result))
            return result

    def substitute(path, *args, **kwargs):
        if path == target and not attempts:
            attempts.append(True)
            return ObservedFile(real_open(outside, *args, **kwargs))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", substitute)
    try:
        scan(target, select=[rule])
    except (ValueError, OSError):
        pass
    assert attempts, "The selected format was not exercised"
    assert not external_reads, "The parser consumed bytes from an opened object outside the root"
