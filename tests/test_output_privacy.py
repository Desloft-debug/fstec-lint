"""Behavioral security regressions. All credentials are synthetic test markers."""

import json
import os
import subprocess
import sys
from dataclasses import asdict

import pytest
from integration_helpers import displayed_path, displayed_uri

from fstec_lint import baseline
from fstec_lint.checks import compose_checks, postgres_checks
from fstec_lint.cli import main
from fstec_lint.engine import scan
from fstec_lint.parsers.compose import parse_compose
from fstec_lint.parsers.postgres import parse_pg_hba
from fstec_lint.reporters import html, json_reporter, passport, sarif, text

MARKER = "SYNTHETIC_TEST_CREDENTIAL_817c"
OTHER = "SYNTHETIC_TEST_ROTATED_92ea"
CASES = ["compose-dash", "compose-equals", "compose-literal", "hba-ldap", "hba-trust", "hba-md5"]
REPORTERS = {
    "text": text,
    "json": json_reporter,
    "html": html,
    "sarif": sarif,
    "passport": passport,
}


def _case(tmp_path, case, marker=MARKER):
    if case.startswith("compose"):
        value = {
            "compose-dash": "${PASSWORD:-" + marker + "}",
            "compose-equals": "${PASSWORD:=" + marker + "}",
            "compose-literal": marker,
        }[case]
        path = tmp_path / "compose.yaml"
        path.write_text(
            "# synthetic only\nservices:\n  app:\n    environment:\n      PASSWORD: "
            + value
            + "\n",
            encoding="utf-8",
        )
        return path, "C004", 4
    method = case.removeprefix("hba-")
    path = tmp_path / "pg_hba.conf"
    # trust/md5 options deliberately exercise the parser's permissive handling;
    # ldap is the server-valid secret-bearing P002 case, not a P001 predicate.
    path.write_text(
        "# synthetic only\n" + f"host all all 0.0.0.0/0 {method} ldapbindpasswd={marker}\n",
        encoding="utf-8",
    )
    return path, "P002" if method == "ldap" else "P001", 2


def _findings(path, rule_id, line):
    result = scan(path, select=[rule_id])
    assert result.errors == []
    assert len(result.findings) == 1, "redaction must not remove the finding"
    finding = result.findings[0]
    assert (finding.rule.id, finding.file, finding.line) == (rule_id, str(path), line)
    assert finding.location and finding.detail
    if rule_id == "C004":
        assert "PASSWORD" in finding.detail
        assert finding.location == "service:app"
    elif rule_id == "P001":
        assert "trust" in finding.detail or "md5" in finding.detail
    else:
        assert "0.0.0.0/0" in finding.detail
    return result.findings


def _report_contract(rendered, fmt, path, rule_id, line):
    assert rendered.strip()
    reported_file = displayed_path(path)
    if fmt == "json":
        entries = json.loads(rendered)
        assert len(entries) == 1
        assert (entries[0]["rule_id"], entries[0]["file"], entries[0]["line"]) == (
            rule_id,
            reported_file,
            line,
        )
    elif fmt == "sarif":
        entries = json.loads(rendered)["runs"][0]["results"]
        assert len(entries) == 1 and entries[0]["ruleId"] == rule_id
        location = entries[0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == displayed_uri(path)
        assert location["region"]["startLine"] == line
    else:
        assert rule_id in rendered and f"{reported_file}:{line}" in rendered


@pytest.mark.parametrize("case", CASES)
def test_public_finding_is_safe_before_reporting(tmp_path, case):
    path, rule_id, line = _case(tmp_path, case)
    findings = _findings(path, rule_id, line)
    serialized = json.dumps(asdict(findings[0]), ensure_ascii=False)
    assert MARKER not in serialized
    assert MARKER not in repr(findings[0])
    assert MARKER not in findings[0].fingerprint()


@pytest.mark.parametrize("case", CASES)
def test_check_api_is_safe_before_finding(tmp_path, case):
    path, rule_id, line = _case(tmp_path, case)
    if rule_id == "C004":
        results = compose_checks.check_secrets_in_environment(parse_compose(path))
    else:
        check = (
            postgres_checks.check_trust_or_md5_auth
            if rule_id == "P001"
            else postgres_checks.check_open_hba_address
        )
        results = check(parse_pg_hba(path))
    assert len(results) == 1 and results[0][2] == line
    assert results[0][0] and results[0][1]
    assert MARKER not in json.dumps(results, ensure_ascii=False)


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("fmt", REPORTERS)
def test_reporter_preserves_safe_finding(tmp_path, case, fmt):
    path, rule_id, line = _case(tmp_path, case)
    rendered = REPORTERS[fmt].render(_findings(path, rule_id, line))
    _report_contract(rendered, fmt, path, rule_id, line)
    assert MARKER not in rendered


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("fmt", REPORTERS)
@pytest.mark.parametrize("destination", ["stdout", "file"])
def test_cli_actual_outputs_are_safe(tmp_path, capsys, case, fmt, destination):
    path, rule_id, line = _case(tmp_path, case)
    output = tmp_path / "saved.report"
    args = [str(path), "--select", rule_id, "--format", fmt, "--fail-on", "low"]
    if destination == "file":
        args += ["--output", str(output)]
    assert main(args) == 1
    captured = capsys.readouterr()
    rendered = output.read_text(encoding="utf-8") if destination == "file" else captured.out
    if destination == "file":
        assert captured.out == ""
    _report_contract(rendered, fmt, path, rule_id, line)
    assert "Traceback" not in captured.err
    assert MARKER not in rendered + captured.out + captured.err


@pytest.mark.parametrize("case", CASES)
def test_baseline_api_and_saved_file_are_safe(tmp_path, capsys, case):
    path, rule_id, line = _case(tmp_path, case)
    findings = _findings(path, rule_id, line)
    saved = tmp_path / "saved-baseline.json"
    assert main([str(path), "--select", rule_id, "--write-baseline", str(saved)]) == 0
    captured = capsys.readouterr()
    raw = saved.read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == rule_id
    assert payload["findings"][0]["file"] == displayed_path(path)
    known = baseline.load(saved)
    assert baseline.apply(findings, known) == ([], 1)
    # Inspect actual read/write surfaces as well as render(), not a print-only mask.
    assert MARKER not in raw + baseline.render(findings) + repr(known)
    assert MARKER not in captured.out + captured.err
    before = saved.read_bytes()
    assert (
        main(
            [
                str(path),
                "--select",
                rule_id,
                "--baseline",
                str(saved),
                "--format",
                "json",
                "--fail-on",
                "low",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert MARKER not in captured.err and saved.read_bytes() == before


@pytest.mark.parametrize("case", ["hba-ldap", "hba-trust", "hba-md5"])
@pytest.mark.parametrize("surface", ["fingerprint", "sarif", "baseline"])
def test_hba_password_rotation_preserves_identity_and_baseline(tmp_path, case, surface):
    path, rule_id, line = _case(tmp_path, case)
    old = _findings(path, rule_id, line)
    saved = tmp_path / "rotation.json"
    saved.write_text(baseline.render(old), encoding="utf-8")
    before = saved.read_bytes()
    _case(tmp_path, case, marker=OTHER)
    new = _findings(path, rule_id, line)
    if surface == "fingerprint":
        assert new[0].fingerprint() == old[0].fingerprint()
    elif surface == "sarif":
        old_sarif = json.loads(sarif.render(old))["runs"][0]["results"][0]
        new_sarif = json.loads(sarif.render(new))["runs"][0]["results"][0]
        assert new_sarif["partialFingerprints"] == old_sarif["partialFingerprints"]
    else:
        assert baseline.apply(new, baseline.load(saved)) == ([], 1)
    assert saved.read_bytes() == before


@pytest.mark.parametrize("method,rule_id", [("ldap", "P002"), ("trust", "P001")])
@pytest.mark.parametrize("surface", ["identity", "partial-baseline"])
def test_hba_distinguishes_records_and_exact_duplicates(tmp_path, method, rule_id, surface):
    path = tmp_path / "pg_hba.conf"
    row = f"host all all 0.0.0.0/0 {method} ldapbindpasswd={MARKER}\n"
    different = f"host reporting analyst 0.0.0.0/0 {method} ldapbindpasswd={MARKER}\n"
    path.write_text("# synthetic only\n" + row + different + row, encoding="utf-8")
    result = scan(path, select=[rule_id])
    assert not result.errors
    result.findings.sort(key=lambda finding: finding.line)
    assert [f.line for f in result.findings] == [2, 3, 4]
    assert all(f.rule.id == rule_id and f.file == str(path) for f in result.findings)
    if surface == "identity":
        assert len({f.fingerprint() for f in result.findings}) == 3
        return
    saved = tmp_path / "partial.json"
    saved.write_text(baseline.render(result.findings[:1]), encoding="utf-8")
    remaining, suppressed = baseline.apply(result.findings, baseline.load(saved))
    assert suppressed == 1 and sorted(f.line for f in remaining) == [3, 4]
    assert MARKER not in baseline.render(result.findings)


@pytest.mark.parametrize("method,rule_id", [("ldap", "P002"), ("trust", "P001")])
@pytest.mark.parametrize("surface", ["api", "cli"])
def test_legacy_hba_requires_explicit_recreation(tmp_path, capsys, method, rule_id, surface):
    path, _, line = _case(tmp_path, "hba-" + method)
    findings = _findings(path, rule_id, line)
    saved = tmp_path / "legacy-v3.json"
    # Historic v3 wire fixture, not an oracle for the new locator algorithm.
    row = f"host all all 0.0.0.0/0 {method} ldapbindpasswd={MARKER}"
    saved.write_text(
        json.dumps(
            {
                "version": 3,
                "findings": [
                    {
                        "rule_id": rule_id,
                        "file": displayed_path(path),
                        "location": "pg_hba: " + row,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    original = saved.read_bytes()
    if surface == "api":
        try:
            known = baseline.load(saved)
        except baseline.BaselineError as error:
            assert MARKER not in str(error) + repr(error)
        else:
            # Safe reading may retain unaffected entries, but cannot silently suppress
            # new HBA identities or return credentials through the public API.
            assert MARKER not in repr(known)
            assert baseline.apply(findings, known) == (findings, 0)
        assert saved.read_bytes() == original
        return
    code = main(
        [
            str(path),
            "--select",
            rule_id,
            "--baseline",
            str(saved),
            "--format",
            "json",
            "--fail-on",
            "low",
        ]
    )
    captured = capsys.readouterr()
    assert code in (1, 2), "legacy data must not hide the finding and return success"
    assert "baseline" in captured.err.lower()
    assert "--write-baseline" in captured.err, "require actionable explicit regeneration"
    assert MARKER not in captured.out + captured.err
    assert "Traceback" not in captured.err
    if code == 1:
        _report_contract(captured.out, "json", path, rule_id, line)
    assert saved.read_bytes() == original


def test_unaffected_hand_authored_v3_remains_compatible(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "compose.yaml"
    path.write_text("services:\n  app:\n    privileged: true\n", encoding="utf-8")
    saved = tmp_path / "safe-v3.json"
    saved.write_text(
        json.dumps(
            {
                "version": 3,
                "findings": [
                    {"rule_id": "C002", "file": "compose.yaml", "location": "service:app"}
                ],
            }
        ),
        encoding="utf-8",
    )
    before = saved.read_bytes()
    assert baseline.load(saved) == {"C002|compose.yaml|service:app"}
    assert (
        main(
            [
                str(path),
                "--select",
                "C002",
                "--baseline",
                str(saved),
                "--format",
                "json",
                "--fail-on",
                "low",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == []
    assert saved.read_bytes() == before


@pytest.mark.parametrize("bad", ["yaml", "baseline-json", "baseline-fields", "output-path"])
def test_error_channels_do_not_echo_secrets(tmp_path, capsys, bad):
    path, rule_id, _ = _case(tmp_path, "compose-dash")
    args = [str(path), "--select", rule_id, "--fail-on", "none"]
    if bad == "yaml":
        path.write_text("services:\n  app: [" + MARKER + "\n", encoding="utf-8")
        expected = 3
    elif bad.startswith("baseline"):
        saved = tmp_path / "bad.json"
        saved.write_text(
            '{"version":3,"findings":['
            + json.dumps(MARKER)
            + ("]}" if bad == "baseline-fields" else ""),
            encoding="utf-8",
        )
        args += ["--baseline", str(saved)]
        with pytest.raises(baseline.BaselineError) as caught:
            baseline.load(saved)
        assert MARKER not in str(caught.value) + repr(caught.value)
        expected = 2
    else:
        args += ["--output", str(tmp_path / "missing-parent" / "report.json")]
        expected = 2
    assert main(args) == expected
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert MARKER not in captured.out + captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("case", ["compose-dash", "hba-ldap"])
def test_real_process_streams_and_exit_code(tmp_path, case):
    path, rule_id, line = _case(tmp_path, case)
    process = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "fstec_lint",
            str(path),
            "--select",
            rule_id,
            "--format",
            "json",
            "--fail-on",
            "low",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    assert process.returncode == 1
    _report_contract(process.stdout, "json", path, rule_id, line)
    assert MARKER not in process.stdout + process.stderr


@pytest.mark.parametrize("value", ["${PASSWORD}", "$PASSWORD", "${PASSWORD:-}", "${PASSWORD:=}"])
def test_c004_nonsecret_references_are_not_findings(tmp_path, value):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services:\n  app:\n    environment:\n      PASSWORD: " + value + "\n", encoding="utf-8"
    )
    result = scan(path, select=["C004"])
    assert not result.errors and result.findings == []


@pytest.mark.parametrize("case", ["compose-dash", "hba-ldap"])
def test_suppression_and_selection_still_work(tmp_path, case):
    path, rule_id, line = _case(tmp_path, case)
    _findings(path, rule_id, line)
    assert scan(path, select=[rule_id], ignore=[rule_id]).findings == []
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[line - 1] += "  # fstec-lint: ignore " + rule_id
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = scan(path, select=[rule_id])
    assert result.errors == [] and result.findings == [] and result.suppressed == 1


@pytest.mark.parametrize(
    "rule_id,row",
    [
        ("P001", "host all all 10.0.0.0/24 scram-sha-256"),
        ("P002", "host all all 10.0.0.0/24 ldap ldapbindpasswd=" + MARKER),
    ],
)
def test_hba_negative_controls(tmp_path, rule_id, row):
    path = tmp_path / "pg_hba.conf"
    path.write_text(row + "\n", encoding="utf-8")
    result = scan(path, select=[rule_id])
    assert not result.errors and result.findings == []
