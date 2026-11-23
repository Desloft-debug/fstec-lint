"""Scanners fail closed when opened-file validation does not succeed."""

import pytest

from fstec_lint.engine import scan
from fstec_lint.parsers import base


@pytest.mark.parametrize(
    "filename,body,rule",
    [
        ("compose.yaml", "services: {app: {image: alpine:3.20}}\n", "C002"),
        ("Dockerfile", "FROM alpine:3.20\nUSER 1000\n", "D001"),
        ("pg_hba.conf", "host all all 127.0.0.1/32 scram-sha-256\n", "P001"),
    ],
)
def test_scan_requires_opened_file_validation(tmp_path, monkeypatch, filename, body, rule):
    target = tmp_path / filename
    target.write_text(body, encoding="utf-8")
    attempts = []
    original = base._opened_path

    def unavailable(fd):
        path = original(fd)
        if path == target.resolve():
            attempts.append(fd)
            raise ValueError("opened file validation unavailable")
        return path

    monkeypatch.setattr(base, "_opened_path", unavailable)
    result = scan(target, select=[rule])
    assert attempts
    assert result.errors
    assert not result.findings
