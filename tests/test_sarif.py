import json
from pathlib import Path

from fstec_lint.engine import scan
from fstec_lint.reporters import sarif

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_sarif_output_is_valid_json_with_expected_shape():
    findings = scan(EXAMPLES / "vulnerable-stack")
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
