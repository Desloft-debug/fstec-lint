"""Proposed contracts, NOT current release promises.

Run explicitly: python -m pytest tests/future_feature_contracts.py.
README excludes PG Include/Compose merge and atomic TOCTOU containment. These
red tests specify future work without counting documented limitations as current
contract violations. No xfail, skip, or change to mandatory test collection.
"""

import pytest
from integration_helpers import cli, write

from fstec_lint.engine import scan
from fstec_lint.parsers.base import BoundedReader


@pytest.mark.parametrize(
    "directive,child",
    [
        ("include 'parts/weak.conf'", "parts/weak.conf"),
        ("include_if_exists 'parts/weak.conf'", "parts/weak.conf"),
        ("include_dir 'parts'", "parts/10.conf"),
    ],
)
def test_proposed_postgresql_effective_include(tmp_path, directive, child):
    write(tmp_path / "postgresql.conf", "ssl=on\n" + directive + "\n")
    origin = write(tmp_path / child, "ssl=off\n")
    result = scan(tmp_path, select=["P005"])
    assert not result.errors
    assert [(f.rule.id, f.file, f.line) for f in result.findings] == [("P005", str(origin), 1)]


def test_proposed_compose_merge_effective_value(tmp_path):
    write(tmp_path / "docker-compose.yml", "services: {app: {privileged: true}}\n")
    write(tmp_path / "docker-compose.override.yml", "services: {app: {privileged: false}}\n")
    result = scan(tmp_path, select=["C002"])
    assert not result.errors and not result.findings


def test_proposed_atomic_containment(tmp_path, monkeypatch):
    from pathlib import Path

    path = write(tmp_path / "selected/config.conf", "safe\n")
    outside = write(tmp_path / "outside.conf", "TEST_SYNTHETIC_OUTSIDE\n")
    expected = outside.read_bytes().decode("utf-8")
    control = tmp_path / "link-control"
    try:
        control.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink race cannot be exercised in this environment: {exc}")
    assert control.read_bytes().decode("utf-8") == expected
    reader = BoundedReader(path.parent)
    real_open = Path.open

    def swapped_open(self, *args, **kwargs):
        if self == path:
            self.rename(self.with_suffix(".saved"))
            self.symlink_to(outside)
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", swapped_open)
    try:
        actual = reader.read(path)
    except (ValueError, OSError):
        return
    assert actual != expected, "outside bytes crossed the checked boundary"


@pytest.mark.parametrize(
    "name,text,rule",
    [("pg_hba.conf", "host all\n", "P001"), ("sshd_config", "MaxAuthTries not-a-number\n", "S006")],
)
def test_proposed_invalid_grammar_is_not_clean(tmp_path, name, text, rule):
    path = write(tmp_path / name, text)
    assert cli([str(path), "--select", rule, "--fail-on", "none"]) == 3
