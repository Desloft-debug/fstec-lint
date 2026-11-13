"""Bounded SSH Include acceptance, synthetic files only.

First-value/order and per-file Match scope follow the supported OLD static parser
contract, not a claim to reproduce every OpenSSH build and effective configuration.
"""

import builtins
import os
import subprocess
from pathlib import Path

import pytest
from integration_helpers import write

from fstec_lint.engine import scan
from fstec_lint.parsers.sshd import parse_sshd_config


def test_internal_include_origin(tmp_path):
    write(tmp_path / "sshd_config", "Include fragments/*.conf\n")
    origin = write(tmp_path / "fragments/10-a.conf", "# synthetic\nPermitRootLogin yes\n")
    for selected in (tmp_path, tmp_path / "sshd_config"):
        result = scan(selected, select=["S001"])
        assert not result.errors and len(result.findings) == 1
        assert (result.findings[0].file, result.findings[0].line) == (str(origin), 2)


@pytest.mark.parametrize("prefix", ["", "PermitRootLogin no\n"])
def test_first_directive_and_lexical_glob_order(tmp_path, prefix):
    path = write(
        tmp_path / "sshd_config", prefix + "Include fragments/*.conf\nPermitRootLogin yes\n"
    )
    write(tmp_path / "fragments/20-b.conf", "PermitRootLogin yes\n")
    write(tmp_path / "fragments/10-a.conf", "PermitRootLogin no\n")
    parsed = parse_sshd_config(path)
    assert parsed["permitrootlogin"] == "no"
    result = scan(tmp_path, select=["S001"])
    assert not result.errors and not result.findings


def test_nested_include_and_multiple_patterns(tmp_path):
    write(tmp_path / "sshd_config", "Include a.conf empty-*.conf\n")
    write(tmp_path / "a.conf", "Include b.conf\n")
    origin = write(tmp_path / "b.conf", "# synthetic\nPermitRootLogin yes\n")
    result = scan(tmp_path, select=["S001"])
    assert not result.errors and len(result.findings) == 1
    assert (result.findings[0].file, result.findings[0].line) == (str(origin), 2)


@pytest.mark.parametrize("where", ["origin", "caller"])
def test_suppression_is_read_from_origin(tmp_path, where):
    caller = "Include a.conf" + (" # fstec-lint: ignore S001" if where == "caller" else "")
    write(tmp_path / "sshd_config", caller + "\n")
    origin = "PermitRootLogin yes" + (" # fstec-lint: ignore S001" if where == "origin" else "")
    write(tmp_path / "a.conf", origin + "\n")
    result = scan(tmp_path, select=["S001"])
    assert not result.errors
    assert len(result.findings) == (0 if where == "origin" else 1)
    assert result.suppressed == (1 if where == "origin" else 0)


@pytest.mark.parametrize("absolute", [False, True])
@pytest.mark.parametrize("direct", [False, True])
def test_external_include_is_rejected_before_io(tmp_path, monkeypatch, absolute, direct):
    root = tmp_path / "selected"
    sibling = write(tmp_path / "sibling.conf", "PermitRootLogin yes\n")
    include = str(sibling) if absolute else "../sibling.conf"
    path = write(root / "sshd_config", f'Include "{include}"\nPermitRootLogin no\n')
    reads = []

    def observe(original):
        def opened(file, *args, **kwargs):
            if not isinstance(file, int) and Path(file).resolve() == sibling.resolve():
                reads.append(str(file))
            return original(file, *args, **kwargs)

        return opened

    monkeypatch.setattr(builtins, "open", observe(builtins.open))
    monkeypatch.setattr(Path, "open", observe(Path.open))
    sibling.read_text(encoding="utf-8")
    assert reads, "positive I/O calibration"
    reads.clear()
    result = scan(path if direct else root, select=["S001"])
    assert not reads, "external Include must be rejected before parser or suppression read"
    assert not result.findings
    assert result.errors, "denied Include must not become a silently complete scan"


def test_absolute_contained_path_and_spaces(tmp_path):
    fragment = write(tmp_path / "fragment with spaces.conf", "PermitRootLogin yes\n")
    write(tmp_path / "sshd_config", f'Include "{fragment.as_posix()}"\n')
    result = scan(tmp_path, select=["S001"])
    assert not result.errors and len(result.findings) == 1
    assert result.findings[0].file == str(fragment)


@pytest.mark.parametrize("cycle", ["self", "mutual"])
def test_include_cycles_are_errors(tmp_path, cycle):
    write(tmp_path / "sshd_config", "Include a.conf\n")
    write(tmp_path / "a.conf", "Include a.conf\n" if cycle == "self" else "Include b.conf\n")
    if cycle == "mutual":
        write(tmp_path / "b.conf", "Include a.conf\n")
    result = scan(tmp_path, select=["S001"])
    assert result.errors and "Traceback" not in repr(result.errors)


@pytest.mark.parametrize("budget", ["depth", "files", "bytes"])
def test_include_work_is_bounded(tmp_path, budget):
    # Stress beyond the proposed 16-depth / 256-file / 8MiB scan budgets.
    if budget == "depth":
        write(tmp_path / "sshd_config", "Include 0.conf\n")
        for i in range(33):
            write(tmp_path / f"{i}.conf", f"Include {i + 1}.conf\n")
        write(tmp_path / "33.conf", "PermitRootLogin yes\n")
    elif budget == "files":
        write(tmp_path / "sshd_config", "Include parts/*.conf\n")
        for i in range(1025):
            write(tmp_path / f"parts/{i:04d}.conf", "# synthetic\n")
    else:
        write(tmp_path / "sshd_config", "Include big.conf\n")
        write(tmp_path / "big.conf", "# synthetic padding\n" * 450000)
    result = scan(tmp_path, select=["S001"])
    assert result.errors, "unbounded or silently ignored Include is not acceptance"


def test_match_scope_inside_include(tmp_path):
    write(tmp_path / "sshd_config", "PermitRootLogin no\nInclude a.conf\nX11Forwarding no\n")
    origin = write(tmp_path / "a.conf", "Match User synthetic\n  PermitRootLogin yes\n")
    result = scan(tmp_path, select=["S001"])
    assert not result.errors and len(result.findings) == 1
    assert (result.findings[0].file, result.findings[0].line) == (str(origin), 2)
    parsed = parse_sshd_config(tmp_path / "sshd_config")
    assert parsed["x11forwarding"] == "no"
    assert "x11forwarding" not in parsed.matches[0].settings


def test_include_inside_match_is_conditional(tmp_path):
    path = write(
        tmp_path / "sshd_config", "PermitRootLogin no\nMatch User synthetic\n  Include a.conf\n"
    )
    write(tmp_path / "a.conf", "PermitRootLogin yes\n")
    parsed = parse_sshd_config(path)
    assert parsed["permitrootlogin"] == "no"
    assert parsed.matches[0].settings["permitrootlogin"] == "yes"


@pytest.mark.parametrize("kind", ["symlink", "junction"])
def test_include_external_directory_link_never_reads_outside(tmp_path, monkeypatch, kind):
    selected = tmp_path / "selected"
    write(selected / "sshd_config", "Include link/*.conf\nPermitRootLogin no\n")
    outside = write(tmp_path / "outside/fragment.conf", "PermitRootLogin yes\n")
    link = selected / "link"
    if kind == "junction":
        if os.name != "nt":
            pytest.skip("Windows junction only")
        p = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
                "$ErrorActionPreference='Stop'; New-Item -ItemType Junction "
                "-Path $env:TEST_LINK -Target $env:TEST_OUT | Out-Null",
            ],
            env={**os.environ, "TEST_LINK": str(link), "TEST_OUT": str(outside.parent)},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=15,
        )
        if p.returncode:
            pytest.skip(f"junction unavailable: exit {p.returncode}: {p.stdout} {p.stderr}")
    else:
        try:
            link.symlink_to(outside.parent, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"symlink unavailable: {type(error).__name__}: {error}")
    assert link.resolve() == outside.parent.resolve()
    original = Path.open
    reads = []

    def opened(path, *args, **kwargs):
        if path.resolve() == outside.resolve():
            reads.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    outside.read_text(encoding="utf-8")
    assert reads
    reads.clear()
    result = scan(selected, select=["S001"])
    assert reads == [] and not result.findings
    assert result.errors


@pytest.mark.parametrize(
    "value,reported",
    [
        ("yes", True),
        ("no", False),
        ("without-password", False),
        ("prohibit-password", False),
        ("forced-commands-only", False),
    ],
)
@pytest.mark.parametrize("context", ["global", "match", "include"])
def test_s001_compatibility_policy(tmp_path, value, reported, context):
    body = f"PermitRootLogin {value}\n"
    if context == "include":
        path = write(tmp_path / "sshd_config", "Include a.conf\n")
        write(tmp_path / "a.conf", body)
    else:
        path = write(
            tmp_path / "sshd_config",
            ("Match User synthetic\n" if context == "match" else "") + body,
        )
    result = scan(path, select=["S001"])
    assert not result.errors and bool(result.findings) is reported


@pytest.mark.parametrize(
    "value,reported", [(None, False), ("2", False), ("1", True), ("1,2", True), ("2,1", True)]
)
def test_s004_policy_and_critical_severity(tmp_path, value, reported):
    path = write(tmp_path / "sshd_config", "" if value is None else f"Protocol {value}\n")
    result = scan(path, select=["S004"])
    assert not result.errors and bool(result.findings) is reported
    assert all(f.rule.severity.name == "CRITICAL" for f in result.findings)


def test_s004_explains_unknown_server_version_limitation():
    from fstec_lint.engine import load_rules

    rule = next(r for r in load_rules() if r.id == "S004")
    assert rule.severity.name == "CRITICAL"
    assert "7.4" in rule.description + rule.remediation, (
        "Protocol 1 is a static policy warning for old servers; OpenSSH 7.4+ removed SSH-1"
    )
