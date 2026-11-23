"""SSH harness integrity tests: mocked fixtures, no system configuration changes."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def ssh(monkeypatch):
    directory = Path(__file__).resolve().parents[1] / "benchmarks"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location("ssh_integrity", directory / "cac_sshd_eval.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fixture_paths(tmp_path):
    scenario = tmp_path / "example.fail.sh"
    scenario.write_text("echo fixture\n")
    base = tmp_path / "base"
    base.write_text("PermitRootLogin no\n")
    return scenario, base


def test_setup_failure_never_scans(ssh, fixture_paths, monkeypatch):
    scenario, base = fixture_paths
    monkeypatch.setattr(ssh, "command", lambda *a, **kw: {"status": "failed", "returncode": 1})
    monkeypatch.setattr(ssh, "scan", lambda *a: pytest.fail("must not scan failed setup"))
    result = ssh.run_scenario(ssh.environment(), scenario.parent, scenario, base, {})
    assert result["status"] == "setup_failed"
    assert result["stages"]["scan"]["status"] == "not_run"
    assert "scenario.sh" in result["rendered_scripts"]["files"]
    assert "ssh/sshd_config" in result["fixture"]["files"]


def test_render_failure_is_not_skipped(ssh, fixture_paths, monkeypatch):
    scenario, base = fixture_paths
    scenario.write_text("echo {{{ missing_variable }}}")
    monkeypatch.setattr(ssh, "command", lambda *a, **kw: pytest.fail("must not execute"))
    result = ssh.run_scenario(ssh.environment(), scenario.parent, scenario, base, {})
    assert result["status"] == "render_failed"
    assert "missing_variable" in result["stages"]["render"]["error"]


@pytest.mark.parametrize("errors", [["parse failed"], ["resource limit"]])
def test_scan_errors_retained(ssh, fixture_paths, monkeypatch, errors):
    scenario, base = fixture_paths
    monkeypatch.setattr(ssh, "command", lambda *a, **kw: {"status": "ok", "returncode": 0})
    monkeypatch.setattr(
        ssh, "sshd_effective", lambda *a: ({"permitrootlogin": "yes"}, {"status": "ok"})
    )
    finding = SimpleNamespace(rule=SimpleNamespace(id="S001"))
    monkeypatch.setattr(ssh, "scan", lambda *a: SimpleNamespace(findings=[finding], errors=errors))
    result = ssh.run_scenario(ssh.environment(), scenario.parent, scenario, base, {})
    assert result["status"] == "scan_failed"
    assert result["rules_hit"] == ["S001"]
    assert result["stages"]["scan"]["errors"] == errors


@pytest.mark.parametrize("status", ["setup_failed", "render_failed", "scan_failed"])
def test_failures_excluded_from_matrices(ssh, fixture_paths, monkeypatch, status):
    scenario, base = fixture_paths
    monkeypatch.setattr(ssh, "MAPPING", {"example": ("S001", "partial")})
    monkeypatch.setattr(ssh, "template_vars", lambda *a: {})
    monkeypatch.setattr(ssh, "scenarios", lambda *a: {scenario.name: scenario})
    monkeypatch.setattr(ssh, "run_scenario", lambda *a: {"status": status})
    result = ssh.evaluate(scenario.parent, base)
    assert result["denominators"] == {"discovered": 1, "cac_classified": 0, "runtime_classified": 0}
    assert result["scenarios"][0]["outcome"] == status
    assert not any(key in result["totals"] for key in ("cac:tn", "cac:fn", "sshd:tn", "sshd:fn"))


def test_platform_skip_is_recorded(ssh, fixture_paths, monkeypatch):
    scenario, base = fixture_paths
    scenario.write_text("# platform = multi_platform_suse\n")
    monkeypatch.setattr(ssh, "MAPPING", {"example": ("S001", "partial")})
    monkeypatch.setattr(ssh, "template_vars", lambda *a: {})
    monkeypatch.setattr(ssh, "scenarios", lambda *a: {scenario.name: scenario})
    monkeypatch.setattr(ssh, "run_scenario", lambda *a: pytest.fail("not applicable"))
    result = ssh.evaluate(scenario.parent, base)
    assert result["scenarios"][0]["outcome"] == "skipped"
    assert result["denominators"]["discovered"] == 1


def test_oracle_invalid_has_raw_but_no_runtime_matrix(ssh, fixture_paths, monkeypatch):
    scenario, base = fixture_paths
    monkeypatch.setattr(ssh, "MAPPING", {"example": ("S001", "partial")})
    monkeypatch.setattr(ssh, "template_vars", lambda *a: {})
    monkeypatch.setattr(ssh, "scenarios", lambda *a: {scenario.name: scenario})
    evidence = {"status": "ok", "rules_hit": [], "stages": {"oracle": {"status": "invalid"}}}
    monkeypatch.setattr(ssh, "run_scenario", lambda *a: evidence)
    result = ssh.evaluate(scenario.parent, base)
    assert result["scenarios"][0]["outcome"] == "fn"
    assert result["scenarios"][0]["sshd_outcome"] == "oracle_invalid"
    assert result["denominators"]["runtime_classified"] == 0


def test_oracle_incomplete_output_not_clean(ssh, tmp_path, monkeypatch):
    monkeypatch.setattr(ssh, "command", lambda *a: {"status": "ok", "stdout": "", "returncode": 0})
    effective, stage = ssh.sshd_effective(tmp_path, tmp_path / "sshd_config")
    assert effective is None
    assert stage["status"] == "failed"


def test_command_interlock(ssh, monkeypatch):
    monkeypatch.delenv("FSTEC_BENCHMARK_DISPOSABLE", raising=False)
    with pytest.raises(RuntimeError):
        ssh.command([sys.executable, "-c", "pass"])


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux process groups")
def test_command_timeout_and_logs(ssh, monkeypatch):
    # Only a disposable, harmless Python subprocess; no shell scenario is executed.
    monkeypatch.setattr(ssh, "require_isolated_container", lambda: None)
    monkeypatch.setattr(ssh, "PROCESS_TIMEOUT", 0.1)
    result = ssh.command([sys.executable, "-c", "import time; time.sleep(2)"])
    assert result["status"] == "timeout"
    result = ssh.command([sys.executable, "-c", "print('x' * 70000)"])
    assert result["status"] == "ok"
    assert result["stdout_truncated"]
    assert len(result["stdout"]) == ssh.LOG_LIMIT


@pytest.mark.parametrize(
    "key,value",
    [
        ("permitrootlogin", "sometimes"),
        ("permitemptypasswords", "false"),
        ("x11forwarding", "maybe"),
        ("maxauthtries", "-1"),
        ("maxauthtries", "1.5"),
        ("maxauthtries", "2147483648"),
        ("loglevel", "unknown"),
    ],
)
def test_oracle_invalid_domains_fail_closed(ssh, tmp_path, monkeypatch, key, value):
    values = dict(
        permitrootlogin="no",
        permitemptypasswords="no",
        x11forwarding="no",
        maxauthtries="6",
        loglevel="INFO",
    )
    values[key] = value
    output = "\n".join(f"{k} {v}" for k, v in values.items())
    monkeypatch.setattr(ssh, "command", lambda *a: {"status": "ok", "stdout": output})
    effective, stage = ssh.sshd_effective(tmp_path, tmp_path / "sshd_config")
    assert effective is None
    assert stage["reason"] == "invalid_effective_parameters"
    assert stage["invalid_parameters"][key] == value


@pytest.mark.parametrize(
    "root", ["yes", "no", "prohibit-password", "without-password", "forced-commands-only"]
)
def test_oracle_valid_domains(ssh, tmp_path, monkeypatch, root):
    output = (
        f"permitrootlogin {root}\npermitemptypasswords no\n"
        "x11forwarding yes\nmaxauthtries 0\nloglevel DEBUG3\n"
    )
    monkeypatch.setattr(ssh, "command", lambda *a: {"status": "ok", "stdout": output})
    effective, stage = ssh.sshd_effective(tmp_path, tmp_path / "sshd_config")
    assert effective is not None
    assert stage["status"] == "ok"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-state regression")
def test_successful_command_kills_background_child(ssh, monkeypatch):
    import os
    import signal
    import time

    monkeypatch.setattr(ssh, "require_isolated_container", lambda: None)
    # Harmless sleeping child; parent exits normally, mirroring shell background work.
    source = (
        "import os,time\npid=os.fork()\n"
        "if pid == 0: time.sleep(10); os._exit(0)\n"
        "print(pid, flush=True)\n"
    )
    result = ssh.command([sys.executable, "-c", source])
    assert result["status"] == "ok"
    pid = int(result["stdout"].strip())
    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{pid}/stat")
            try:
                process_state = stat.read_text().split(") ", 1)[1]
            except (FileNotFoundError, ProcessLookupError):
                # The child may disappear before /proc returns its state.
                break
            if process_state.startswith("Z"):
                break
            time.sleep(0.01)
        else:
            pytest.fail("background descendant remains alive after successful command")
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.mark.parametrize(
    "level,violation",
    [
        (level, level in {"QUIET", "SILENT", "FATAL", "ERROR"})
        for level in [
            "QUIET",
            "SILENT",
            "FATAL",
            "ERROR",
            "INFO",
            "VERBOSE",
            "DEBUG",
            "DEBUG1",
            "DEBUG2",
            "DEBUG3",
        ]
    ],
)
@pytest.mark.parametrize("lowercase", [False, True])
def test_all_loglevel_spellings_valid_and_classified(
    ssh, tmp_path, monkeypatch, level, violation, lowercase
):
    observed = level.lower() if lowercase else level
    output = (
        "permitrootlogin no\npermitemptypasswords no\n"
        f"x11forwarding no\nmaxauthtries 6\nloglevel {observed}\n"
    )
    monkeypatch.setattr(ssh, "command", lambda *a: {"status": "ok", "stdout": output})
    effective, stage = ssh.sshd_effective(tmp_path, tmp_path / "sshd_config")
    assert stage["status"] == "ok"
    assert effective["loglevel"] == observed  # Preserve oracle output, not relabel it.
    assert ssh.ORACLE["S008"](effective) is violation
