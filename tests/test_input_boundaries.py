"""Read boundaries use only synthetic files and unprivileged links."""

import builtins
import os
import subprocess
from pathlib import Path

import pytest
from integration_helpers import displayed_path

from fstec_lint.cli import main
from fstec_lint.engine import scan

CONFIG = "services:\n  app:\n    privileged: true\n"


def _write(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CONFIG, encoding="utf-8")
    return path


def _link(link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"unprivileged symlink unavailable: {type(error).__name__}: {error}")


def test_environment_tmp_path_uses_current_temp(tmp_path):
    expected = Path(os.environ["TEMP"]).resolve()
    for variable in ("TMP", "TMPDIR", "PYTEST_DEBUG_TEMPROOT"):
        assert Path(os.environ[variable]).resolve() == expected
    assert tmp_path.resolve().is_relative_to(expected)
    target = tmp_path / "write-probe.txt"
    target.write_text("synthetic temporary data", encoding="utf-8")
    assert target.read_text(encoding="utf-8") == "synthetic temporary data"


@pytest.mark.parametrize("production_only", [False, True])
@pytest.mark.parametrize("surface", ["api", "io", "cli"])
def test_recursive_external_file_link_is_not_read(
    tmp_path, monkeypatch, capsys, production_only, surface
):
    root = tmp_path / "selected"
    local = _write(root / "compose.yaml")
    outside = _write(tmp_path / "outside" / "compose.yaml")
    link = root / "docker-compose.yml"
    _link(link, outside)
    reads = []
    builtin_open, path_open = builtins.open, Path.open

    def observe(original):
        def opened(file, *args, **kwargs):
            if not isinstance(file, int) and Path(file).resolve() == outside.resolve():
                reads.append(str(file))
            return original(file, *args, **kwargs)

        return opened

    monkeypatch.setattr(builtins, "open", observe(builtin_open))
    monkeypatch.setattr(Path, "open", observe(path_open))
    # Python 3.10 pathlib caches its accessor; patching io.open alone misses it.
    # Calibrate the observer with an explicit synthetic read before observing SUT.
    with outside.open(encoding="utf-8") as control:
        assert control.readline() == "services:\n"
    assert reads == [str(outside)], "I/O observer must detect its positive control"
    reads.clear()
    result = scan(root, select=["C002"], production_only=production_only)
    if surface == "api":
        assert [(f.rule.id, f.file, f.line) for f in result.findings] == [("C002", str(local), 3)]
    elif surface == "io":
        assert reads == [], "check containment before parser/suppression I/O"
    else:
        import json

        args = [str(root), "--select", "C002", "--format", "json", "--fail-on", "none"]
        if production_only:
            args += ["--production-only"]
        assert main(args) == (3 if result.errors else 0)
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err
        entries = json.loads(captured.out)
        assert len(entries) == 1 and entries[0]["rule_id"] == "C002"
        assert entries[0]["file"] == displayed_path(local)
        assert entries[0]["line"] == 3


@pytest.mark.parametrize("explicit", ["target-file", "file-link", "target-root", "directory-link"])
def test_explicit_user_path_may_select_external_tree(tmp_path, explicit):
    outside = _write(tmp_path / "outside" / "compose.yaml")
    selected = tmp_path / "selected"
    selected.mkdir()
    if explicit == "target-file":
        target = outside
    elif explicit == "target-root":
        target = outside.parent
    elif explicit == "file-link":
        target = selected / "compose.yaml"
        _link(target, outside)
    else:
        target = selected / "external"
        _link(target, outside.parent, directory=True)
    result = scan(target, select=["C002"])
    assert not result.errors
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule.id == "C002" and finding.line == 3
    assert Path(finding.file).resolve() == outside.resolve()


def test_recursive_external_directory_link_is_not_followed(tmp_path):
    root = tmp_path / "selected"
    local = _write(root / "compose.yaml")
    outside = _write(tmp_path / "outside" / "compose.yaml")
    _link(root / "external", outside.parent, directory=True)
    result = scan(root, select=["C002"])
    assert [(f.rule.id, f.file, f.line) for f in result.findings] == [("C002", str(local), 3)]


def test_contained_file_link_keeps_useful_scan(tmp_path):
    target = _write(tmp_path / "data" / "safe.txt")
    link = tmp_path / "compose.yaml"
    _link(link, target)
    result = scan(tmp_path, select=["C002"])
    assert not result.errors
    assert [(f.rule.id, f.line) for f in result.findings] == [("C002", 3)]
    assert Path(result.findings[0].file).resolve() == target.resolve()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_recursive_external_junction_is_not_followed(tmp_path):
    root = tmp_path / "selected"
    local = _write(root / "compose.yaml")
    outside = _write(tmp_path / "outside" / "compose.yaml")
    junction = root / "external"
    process = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
            "$ErrorActionPreference='Stop'; New-Item -ItemType Junction "
            "-Path $env:TEST_JUNCTION -Target $env:TEST_TARGET | Out-Null",
        ],
        env={**os.environ, "TEST_JUNCTION": str(junction), "TEST_TARGET": str(outside.parent)},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=15,
    )
    if process.returncode:
        pytest.skip(
            f"unprivileged junction unavailable: exit {process.returncode}: {process.stderr}"
        )
    assert junction.is_dir() and junction.resolve() == outside.parent.resolve()
    result = scan(root, select=["C002"])
    assert [(f.rule.id, f.file, f.line) for f in result.findings] == [("C002", str(local), 3)]
