import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fstec_lint import baseline
from fstec_lint.cli import main
from fstec_lint.engine import scan
from fstec_lint.models import Finding, Rule, Severity

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _finding(rule_id="C009", file="a/docker-compose.yml", location="service:db"):
    rule = Rule(
        id=rule_id,
        title="Тест",
        severity=Severity.MEDIUM,
        measure="ОЦЛ.1",
        measure_title="Обеспечение целостности",
        description="описание",
        remediation="исправление",
        target="compose",
        orders="№21 (ПДн)",
    )
    return Finding(rule=rule, file=file, location=location, detail="что-то не так")


def test_fingerprint_ignores_detail():
    a = _finding()
    b = Finding(rule=a.rule, file=a.file, location=a.location, detail="другой текст")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_distinguishes_location():
    a = _finding(location="service:db")
    b = _finding(location="service:web")
    assert a.fingerprint() != b.fingerprint()


def test_render_is_sorted_and_deterministic():
    findings = [
        _finding(rule_id="C010", location="service:web"),
        _finding(rule_id="C001", location="service:db"),
    ]
    payload = json.loads(baseline.render(findings))
    assert payload["version"] == baseline.BASELINE_VERSION
    assert [e["rule_id"] for e in payload["findings"]] == ["C001", "C010"]
    assert baseline.render(findings) == baseline.render(list(reversed(findings)))


def test_apply_suppresses_known_findings():
    findings = [_finding(rule_id="C001"), _finding(rule_id="C002")]
    known = {findings[0].fingerprint()}
    remaining, suppressed = baseline.apply(findings, known)
    assert suppressed == 1
    assert [f.rule.id for f in remaining] == ["C002"]


def test_apply_keeps_unrelated_findings():
    findings = [_finding(rule_id="C001")]
    remaining, suppressed = baseline.apply(findings, {"C999|other.yml|service:x"})
    assert suppressed == 0
    assert remaining == findings


def test_load_roundtrip(tmp_path):
    findings = [_finding(rule_id="C001"), _finding(rule_id="C002")]
    path = tmp_path / "baseline.json"
    path.write_text(baseline.render(findings), encoding="utf-8")
    assert baseline.load(path) == {f.fingerprint() for f in findings}


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(baseline.BaselineError, match="не найден"):
        baseline.load(tmp_path / "nope.json")


def test_load_corrupt_file_raises(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{не json", encoding="utf-8")
    with pytest.raises(baseline.BaselineError, match="повреждён"):
        baseline.load(path)


def test_load_rejects_unknown_version(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"version": 999, "findings": []}), encoding="utf-8")
    with pytest.raises(baseline.BaselineError, match="версия baseline"):
        baseline.load(path)


def test_cli_write_then_use_baseline_silences_everything(tmp_path, monkeypatch, capsys):
    # относительные пути в baseline считаются от cwd, поэтому фиксируем его
    monkeypatch.chdir(EXAMPLES.parent)
    baseline_path = tmp_path / "baseline.json"

    assert main([str(EXAMPLES / "vulnerable-stack"), "--write-baseline", str(baseline_path)]) == 0
    capsys.readouterr()

    # весь текущий долг зафиксирован — даже с самым строгим порогом сборка зелёная
    assert (
        main(
            [
                str(EXAMPLES / "vulnerable-stack"),
                "--baseline",
                str(baseline_path),
                "--fail-on",
                "low",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "нарушений не найдено" in captured.out
    assert "подавлено baseline-ом" in captured.err


def test_cli_baseline_still_reports_new_findings(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(EXAMPLES.parent)
    target = EXAMPLES / "vulnerable-stack"

    findings = scan(target).findings
    partial = [f for f in findings if f.rule.id != "C002"]
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(baseline.render(partial), encoding="utf-8")

    exit_code = main([str(target), "--baseline", str(baseline_path), "--fail-on", "critical"])
    out = capsys.readouterr().out

    assert exit_code == 1
    assert "C002" in out
    assert "C009" not in out


def test_cli_missing_baseline_file_exits_2(tmp_path, capsys):
    exit_code = main(
        [str(EXAMPLES / "hardened-stack"), "--baseline", str(tmp_path / "absent.json")]
    )
    assert exit_code == 2
    assert "не найден" in capsys.readouterr().err


def test_relative_file_falls_back_to_absolute_outside_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = os.path.join(os.sep, "somewhere", "else", "docker-compose.yml")
    finding = _finding(file=outside)
    # цепочка '../../..' до чужого каталога нечитаема и ничего не даёт
    assert finding.relative_file() == outside


# Synthetic markers, never real credentials. Check API diagnostics and CLI stderr
# independently so a CLI-only redaction cannot hide a leaking BaselineError.
DIAGNOSTIC_SENTINEL = "SYNTHETIC_BASELINE_SENTINEL_742c"


@pytest.mark.parametrize(
    "payload",
    [
        {"version": DIAGNOSTIC_SENTINEL, "findings": []},
        {"version": {"nested": DIAGNOSTIC_SENTINEL}, "findings": []},
        {"version": [DIAGNOSTIC_SENTINEL], "findings": []},
        {"version": 3, "findings": [DIAGNOSTIC_SENTINEL]},
        {"version": 3, "findings": [{"file": DIAGNOSTIC_SENTINEL}]},
        {"version": 3, "findings": [[DIAGNOSTIC_SENTINEL]]},
    ],
)
@pytest.mark.parametrize("surface", ["exception", "stderr"])
def test_diagnostic_sentinel_never_reflected(tmp_path, capsys, payload, surface):
    path = tmp_path / "damaged.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    if surface == "exception":
        with pytest.raises(baseline.BaselineError) as caught:
            baseline.load(path)
        assert DIAGNOSTIC_SENTINEL not in str(caught.value)
        assert DIAGNOSTIC_SENTINEL not in repr(caught.value)
    else:
        assert main([str(tmp_path), "--baseline", str(path)]) == 2
        captured = capsys.readouterr()
        assert captured.err.strip()
        assert "Traceback" not in captured.err
        assert DIAGNOSTIC_SENTINEL not in captured.err + captured.out


def test_explicit_v3_baseline_compatibility(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:latest\n    privileged: true\n", encoding="utf-8"
    )
    path = tmp_path / "v3.json"
    # Hand-authored oracle, independent of render()/fingerprint().
    path.write_text(
        json.dumps(
            {
                "version": 3,
                "findings": [
                    {"rule_id": "C002", "file": "docker-compose.yml", "location": "service:db"}
                ],
            }
        ),
        encoding="utf-8",
    )
    assert baseline.load(path) == {"C002|docker-compose.yml|service:db"}
    assert (
        main(
            [
                str(tmp_path),
                "--select",
                "C002",
                "--baseline",
                str(path),
                "--format",
                "json",
                "--fail-on",
                "low",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == []


@pytest.mark.parametrize("version", [3.0, True, False, None])
def test_baseline_version_requires_integer_v3(tmp_path, capsys, version):
    path = tmp_path / "wrong-version.json"
    path.write_text(json.dumps({"version": version, "findings": []}), encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load(path)
    assert main([str(tmp_path), "--baseline", str(path)]) == 2
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "raw",
    [
        b"\xffSYNTHETIC_BASELINE_SENTINEL_742c",
        b'{"version": "SYNTHETIC_BASELINE_SENTINEL_742c", bad}',
    ],
)
def test_baseline_encoding_and_json_errors_do_not_reflect_data(tmp_path, capsys, raw):
    path = tmp_path / "malformed.json"
    path.write_bytes(raw)
    with pytest.raises(baseline.BaselineError) as caught:
        baseline.load(path)
    assert DIAGNOSTIC_SENTINEL not in str(caught.value)
    assert DIAGNOSTIC_SENTINEL not in repr(caught.value)
    assert main([str(tmp_path), "--baseline", str(path)]) == 2
    assert DIAGNOSTIC_SENTINEL not in capsys.readouterr().err


def test_baseline_directory_is_usage_error(tmp_path, capsys):
    with pytest.raises(baseline.BaselineError):
        baseline.load(tmp_path)
    assert main([str(tmp_path), "--baseline", str(tmp_path)]) == 2
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["deep_document", "deep_entry", "large_integer"])
@pytest.mark.parametrize("surface", ["api", "cli"])
def test_baseline_resource_errors_are_usage_errors(tmp_path, kind, surface):
    if kind == "large_integer":
        text = '{"note":"' + DIAGNOSTIC_SENTINEL + '","version":' + "9" * 5000 + "}"
    else:
        nested = "[" * 1500 + json.dumps(DIAGNOSTIC_SENTINEL) + "]" * 1500
        text = (
            nested
            if kind == "deep_document"
            else (
                '{"version":3,"findings":[{"rule_id":"C002","file":"compose.yaml","location":'
                + nested
                + "}]}"
            )
        )
    path = tmp_path / "resource.json"
    path.write_text(text, encoding="utf-8")
    if surface == "api":
        with pytest.raises(baseline.BaselineError) as caught:
            baseline.load(path)
        assert DIAGNOSTIC_SENTINEL not in str(caught.value) + repr(caught.value)
        assert "9" * 100 not in str(caught.value)
    else:
        p = subprocess.run(
            [sys.executable, "-B", "-m", "fstec_lint", str(tmp_path), "--baseline", str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        )
        assert p.returncode == 2
        assert p.stderr.strip()
        assert "Traceback" not in p.stderr
        assert DIAGNOSTIC_SENTINEL not in p.stdout + p.stderr
        assert "9" * 100 not in p.stderr


def test_baseline_fingerprint_recursion_is_safe(tmp_path, monkeypatch, capsys):
    # Fault injection isolates the post-decode defense: the normal JSON decoder
    # rejects this depth first. Only native JSON-compatible types are injected.
    nested = DIAGNOSTIC_SENTINEL
    for _ in range(1500):
        nested = [nested]
    payload = {
        "version": 3,
        "findings": [{"rule_id": "C002", "file": "compose.yaml", "location": nested}],
    }
    path = tmp_path / "injected.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(baseline.json, "loads", lambda _: payload)
    with pytest.raises(baseline.BaselineError) as caught:
        baseline.load(path)
    assert DIAGNOSTIC_SENTINEL not in str(caught.value) + repr(caught.value)
    assert main([str(tmp_path), "--baseline", str(path)]) == 2
    captured = capsys.readouterr()
    assert DIAGNOSTIC_SENTINEL not in captured.out + captured.err
    assert "Traceback" not in captured.err


def test_baseline_large_valid_v3_remains_compatible(tmp_path, capsys):
    entries = [
        {
            "rule_id": "C002",
            "file": f"directory-{i}/compose.yaml",
            "location": "service:" + "x" * 256,
        }
        for i in range(1024)
    ]
    path = tmp_path / "large-valid.json"
    path.write_text(json.dumps({"version": 3, "findings": entries}), encoding="utf-8")
    known = baseline.load(path)
    assert len(known) == 1024
    assert "C002|directory-0/compose.yaml|service:" + "x" * 256 in known
    assert "C002|directory-1023/compose.yaml|service:" + "x" * 256 in known
    assert main([str(tmp_path), "--baseline", str(path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == []
