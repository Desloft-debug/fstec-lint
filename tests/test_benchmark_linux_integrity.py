"""Harness-only tests: no external scripts or system configuration are executed."""

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import jinja2
import pytest

BENCH = Path(__file__).parents[1] / "benchmarks"
sys.path.insert(0, str(BENCH))
spec = importlib.util.spec_from_file_location("linux_integrity_eval", BENCH / "cac_linux_eval.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_strict_render():
    with pytest.raises(jinja2.UndefinedError):
        mod.environment().from_string("x={{{ MISSING }}}").render()


@pytest.fixture
def harness(tmp_path, monkeypatch):
    rule = "accounts_password_pam_minlen"
    paths = []
    monkeypatch.setattr(mod, "MAPPING", {rule: ("A002", "minlen")})
    monkeypatch.setattr(mod, "context", lambda *a: {})
    monkeypatch.setattr(mod, "scenarios", lambda *a: paths)
    monkeypatch.setattr(mod, "pwquality_oracle", lambda *a: {"status": "not_available"})

    def add(name, text="echo ok"):
        path = tmp_path / name
        path.write_text(text)
        paths.append(path)

    return tmp_path, add


def fake_run(monkeypatch, tmp_path, status="ok", errors=()):
    class Holder:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    root = tmp_path / "generated"
    (root / "etc").mkdir(parents=True)
    monkeypatch.setattr(mod, "run", lambda *a: (root, Holder(), {"status": status}))
    monkeypatch.setattr(mod, "scan", lambda *a: SimpleNamespace(findings=[], errors=errors))


def test_failed_setup_not_tn(harness, monkeypatch):
    root, add = harness
    add("a.pass.sh")
    fake_run(monkeypatch, root, "failed")
    monkeypatch.setattr(mod, "scan", lambda *a: pytest.fail("scan must not run"))
    report = mod.evaluate(root, root / "unused")
    assert report["totals"] == {"setup_failed": 1}
    assert report["counts"]["classified_raw"] == 0


def test_scan_error_not_fn(harness, monkeypatch):
    root, add = harness
    add("a.fail.sh")
    fake_run(monkeypatch, root, errors=["parse failed"])
    assert mod.evaluate(root, root / "unused")["totals"] == {"scan_failed": 1}


def test_all_exclusions_recorded(harness, monkeypatch):
    root, add = harness
    add("a.pass.sh", "{{{ MISSING }}}")
    add("b.pass.sh", "# platform = Ubuntu 24.04")
    report = mod.evaluate(root, root / "unused")
    assert report["totals"] == {"render_failed": 1, "skipped": 1}
    assert report["counts"]["discovered"] == 2


def test_policy_runtime_remain_separate(harness, monkeypatch):
    root, add = harness
    add("a.fail.sh")
    fake_run(monkeypatch, root)
    monkeypatch.setattr(
        mod, "pwquality_oracle", lambda *a: {"status": "ok", "expected_violation": False}
    )
    report = mod.evaluate(root, root / "unused")
    row = report["scenarios"][0]
    assert row["outcome"] == "fn"
    assert row["runtime_outcome"] == "tn"
    assert row["policy_runtime_disagreement"] is True


def test_successful_setup_cleans_process_group(tmp_path, monkeypatch):
    calls = []

    class Process:
        pid = 123456
        returncode = 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(mod, "require_isolated_container", lambda: None)
    monkeypatch.setattr(mod.subprocess, "Popen", lambda *a, **k: Process())
    monkeypatch.setattr(mod.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    result = mod.execute_setup(tmp_path)
    assert result["status"] == "ok"
    assert calls == [(123456, mod.signal.SIGKILL)]
