"""Missing SEC-F-02/F-03 behavior; all credentials are synthetic.

Compose branch expectations follow the product specification:
https://docs.docker.com/reference/compose-file/interpolation/
Neither environment interpolation nor Docker/shell execution is used as oracle.
Existing HBA, legacy-v3, alias and Action contracts remain in their own suites.
"""

import json
from dataclasses import asdict

import pytest

from fstec_lint import baseline
from fstec_lint.checks import compose_checks, dockerfile_checks
from fstec_lint.cli import main
from fstec_lint.engine import scan
from fstec_lint.parsers.compose import parse_compose
from fstec_lint.parsers.dockerfile import parse_dockerfile
from fstec_lint.reporters import html, json_reporter, passport, sarif, text

MARKER = "SYNTHETIC_FINAL_SECRET_29f8"
REPORTERS = {
    "text": text,
    "json": json_reporter,
    "html": html,
    "sarif": sarif,
    "passport": passport,
}
COMMANDS = {
    "D002": f"ADD https://user:{MARKER}@example.invalid/file /file",
    "D003": f"ARG API_TOKEN={MARKER}",
    "D005": f"RUN curl -u user:{MARKER} https://example.invalid/setup | sh",
}


def _docker(tmp_path, rule_id):
    path = tmp_path / "Dockerfile"
    path.write_text("FROM alpine:3.20\n" + COMMANDS[rule_id] + "\n", encoding="utf-8")
    return path


def _finding(path, rule_id):
    result = scan(path, select=[rule_id])
    assert result.errors == [] and len(result.findings) == 1
    finding = result.findings[0]
    assert (finding.rule.id, finding.file, finding.line) == (rule_id, str(path), 2)
    assert finding.detail and finding.location
    return result.findings


@pytest.mark.parametrize("rule_id", COMMANDS)
def test_docker_check_result_is_private_before_finding(tmp_path, rule_id):
    results = dockerfile_checks.REGISTRY[rule_id](parse_dockerfile(_docker(tmp_path, rule_id)))
    assert len(results) == 1 and results[0][2] == 2
    assert results[0][0] and results[0][1]
    assert MARKER not in json.dumps(results)


@pytest.mark.parametrize("rule_id", COMMANDS)
def test_docker_finding_location_and_fingerprint_are_private(tmp_path, rule_id):
    finding = _finding(_docker(tmp_path, rule_id), rule_id)[0]
    assert MARKER not in json.dumps(asdict(finding)) + repr(finding) + finding.fingerprint()


@pytest.mark.parametrize("rule_id", COMMANDS)
@pytest.mark.parametrize("fmt", REPORTERS)
def test_docker_all_reporters_are_private(tmp_path, rule_id, fmt):
    rendered = REPORTERS[fmt].render(_finding(_docker(tmp_path, rule_id), rule_id))
    assert rule_id in rendered
    assert MARKER not in rendered


@pytest.mark.parametrize("rule_id", COMMANDS)
@pytest.mark.parametrize("fmt", REPORTERS)
@pytest.mark.parametrize("destination", ["stdout", "file"])
def test_docker_cli_outputs_keep_detection_without_disclosure(
    tmp_path, capsys, rule_id, fmt, destination
):
    path = _docker(tmp_path, rule_id)
    output = tmp_path / "report.txt"
    args = [str(path), "--select", rule_id, "--format", fmt, "--fail-on", "low"]
    if destination == "file":
        args += ["--output", str(output)]
    assert main(args) == 1
    captured = capsys.readouterr()
    rendered = output.read_text(encoding="utf-8") if destination == "file" else captured.out
    assert rule_id in rendered and rendered.strip()
    assert MARKER not in rendered + captured.out + captured.err
    assert "Traceback" not in captured.err
    if destination == "file":
        assert captured.out == ""


@pytest.mark.parametrize("rule_id", COMMANDS)
def test_docker_written_baseline_v3_is_private_and_usable(tmp_path, capsys, rule_id):
    path = _docker(tmp_path, rule_id)
    findings = _finding(path, rule_id)
    saved = tmp_path / "baseline.json"
    assert main([str(path), "--select", rule_id, "--write-baseline", str(saved)]) == 0
    captured = capsys.readouterr()
    raw = saved.read_text(encoding="utf-8")
    assert json.loads(raw)["version"] == 3
    known = baseline.load(saved)
    assert MARKER not in raw + repr(known) + baseline.render(findings) + captured.out + captured.err
    assert baseline.apply(findings, known) == ([], 1)
    assert main([str(path), "--select", rule_id, "--baseline", str(saved), "--fail-on", "low"]) == 0


@pytest.mark.parametrize("rule_id", COMMANDS)
def test_docker_privacy_fix_preserves_suppression(tmp_path, rule_id):
    path = _docker(tmp_path, rule_id)
    _finding(path, rule_id)
    path.write_text(
        "FROM alpine:3.20\n# fstec-lint: ignore " + rule_id + "\n" + COMMANDS[rule_id] + "\n",
        encoding="utf-8",
    )
    result = scan(path, select=[rule_id])
    assert not result.errors and not result.findings and result.suppressed == 1


def _compose(tmp_path, value, form):
    path = tmp_path / "compose.yaml"
    entry = "      PASSWORD: " if form == "mapping" else "      - PASSWORD="
    path.write_text(
        "services:\n  app:\n    environment:\n" + entry + value + "\n", encoding="utf-8"
    )
    return path


@pytest.mark.parametrize("operator", ["-", ":+", "+"])
@pytest.mark.parametrize("form", ["mapping", "list"])
@pytest.mark.parametrize("surface", ["direct", "cli"])
def test_c004_conditional_literal_is_never_clean(tmp_path, capsys, operator, form, surface):
    path = _compose(tmp_path, "${PASSWORD" + operator + MARKER + "}", form)
    if surface == "direct":
        results = compose_checks.check_secrets_in_environment(parse_compose(path))
        assert len(results) == 1 and results[0][0] == "service:app" and results[0][2] == 3
        assert "PASSWORD" in results[0][1] and MARKER not in repr(results)
    else:
        assert main([str(path), "--select", "C004", "--format", "json", "--fail-on", "high"]) == 1
        captured = capsys.readouterr()
        entries = json.loads(captured.out)
        assert len(entries) == 1 and entries[0]["rule_id"] == "C004" and entries[0]["line"] == 3
        assert MARKER not in captured.out + captured.err


@pytest.mark.parametrize("value", ["${PASSWORD-}", "${PASSWORD:+}", "${PASSWORD+}"])
@pytest.mark.parametrize("form", ["mapping", "list"])
def test_c004_empty_conditional_branch_has_no_secret(tmp_path, value, form):
    result = scan(_compose(tmp_path, value, form), select=["C004"])
    assert not result.errors and result.findings == []
