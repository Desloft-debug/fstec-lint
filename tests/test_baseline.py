import json
import os
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

    findings = scan(target)
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
    finding = _finding(file=os.path.join(os.sep, "somewhere", "else", "docker-compose.yml"))
    # относительный путь может уйти вверх через .., но обязан остаться строкой
    assert isinstance(finding.relative_file(), str)
