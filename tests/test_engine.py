from pathlib import Path

from fstec_lint.engine import scan
from fstec_lint.models import Severity

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_vulnerable_stack_triggers_expected_rules():
    findings = scan(EXAMPLES / "vulnerable-stack").findings
    ids = {f.rule.id for f in findings}

    for expected in (
        "C001",
        "C002",
        "C003",
        "C004",
        "C005",
        "C006",
        "C007",
        "C008",
        "C011",
        "C012",
        "C013",
        "C014",
        "C015",
        "P001",
        "P002",
        "P007",
        "P008",
        "S001",
        "S002",
        "S005",
        "S006",
        "U001",
        "U002",
        "U003",
        "U004",
        "U005",
        "D001",
        "D002",
        "D003",
        "D004",
        "D005",
        "D006",
    ):
        assert expected in ids, f"ожидалось нарушение {expected}, найдено: {sorted(ids)}"

    assert any(f.rule.severity == Severity.CRITICAL for f in findings)


def test_hardened_stack_has_no_high_or_critical_findings():
    findings = scan(EXAMPLES / "hardened-stack").findings
    blocking = [f for f in findings if f.rule.severity >= Severity.HIGH]
    assert blocking == [], (
        f"неожиданные high/critical находки: {[(f.rule.id, f.location) for f in blocking]}"
    )


def test_scan_empty_dir_returns_no_findings(tmp_path):
    assert scan(tmp_path).findings == []
