import json
from pathlib import Path

from fstec_lint.engine import scan
from fstec_lint.reporters import sarif

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_sarif_output_is_valid_json_with_expected_shape():
    findings = scan(EXAMPLES / "vulnerable-stack").findings
    payload = json.loads(sarif.render(findings))

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "fstec-lint"
    assert len(run["results"]) == len(findings)

    rule_ids_in_results = {r["ruleId"] for r in run["results"]}
    rule_ids_declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids_in_results <= rule_ids_declared


def test_sarif_empty_findings():
    payload = json.loads(sarif.render([]))
    assert payload["runs"][0]["results"] == []
    assert payload["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_uses_real_line_numbers():
    findings = scan(EXAMPLES / "vulnerable-stack").findings
    payload = json.loads(sarif.render(findings))
    results = payload["runs"][0]["results"]

    lines = {
        r["ruleId"]: r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results
    }
    # S001 стоит второй строкой sshd_config — раньше все находки лежали на строке 1
    assert lines["S001"] == 2
    assert all(line >= 1 for line in lines.values())


def test_sarif_fingerprints_survive_line_shift():
    from fstec_lint.models import Finding, Rule, Severity

    rule = Rule(
        id="C001",
        title="t",
        severity=Severity.HIGH,
        measure="УПД.4",
        measure_title="mt",
        description="d",
        remediation="r",
        target="compose",
    )
    before = Finding(
        rule=rule, file="docker-compose.yml", location="service:web", detail="x", line=3
    )
    after = Finding(
        rule=rule, file="docker-compose.yml", location="service:web", detail="x", line=91
    )

    prints = [
        json.loads(sarif.render([f]))["runs"][0]["results"][0]["partialFingerprints"]
        for f in (before, after)
    ]
    assert prints[0] == prints[1]
    assert prints[0]["fstecLintFingerprint/v1"]
