import json

import pytest

from fstec_lint.cli import main
from fstec_lint.engine import load_rules, scan
from fstec_lint.regulatory import metadata


@pytest.mark.parametrize(
    ("code", "setting"),
    [("U006", "ProtectKernelTunables"), ("U007", "ProtectKernelModules")],
)
@pytest.mark.parametrize("value", ["NO", "off", "false", "0", "n", "f"])
def test_explicit_disabled_from_winning_fragment(tmp_path, code, setting, value):
    unit = tmp_path / "app.service"
    unit.write_text(f"[Service]\n{setting}=yes\n", encoding="utf-8")
    fragment = tmp_path / "service.d" / "local.conf"
    fragment.parent.mkdir()
    fragment.write_text(f"[Service]\n{setting}={value}\n", encoding="utf-8")
    result = scan(unit, select=[code], strict_scope=True)
    assert not result.errors
    assert [(f.rule.id, f.file, f.line) for f in result.findings] == [(code, str(fragment), 2)]


@pytest.mark.parametrize("setting", ["", "ProtectKernelModules=yes\n", "ProtectKernelModules=t\n"])
def test_absent_or_enabled_is_not_a_finding(tmp_path, setting):
    unit = tmp_path / "app.service"
    unit.write_text("[Service]\n" + setting, encoding="utf-8")
    result = scan(unit, select=["U007"], strict_scope=True)
    assert not result.errors and not result.findings


@pytest.mark.parametrize("value", ["", "uncertain"])
def test_strict_invalid_kernel_value_is_not_clean(tmp_path, capsys, value):
    unit = tmp_path / "app.service"
    unit.write_text(f"[Service]\nUser=svc\nProtectKernelTunables={value}\n", encoding="utf-8")
    assert (
        main([str(unit), "--select", "U001,U006", "--strict-scope", "--format", "json-context"])
        == 3
    )
    result = json.loads(capsys.readouterr().out)
    assert result["partial"]
    assert [(err["reason"], err["rule_id"]) for err in result["errors"]] == [
        ("unresolved_value", "U006"),
    ]


@pytest.mark.parametrize("code", ["U006", "U007"])
def test_new_rules_reference_117_as_related_not_compliance(code):
    rule = next(rule for rule in load_rules() if rule.id == code)
    refs = metadata(rule)
    assert refs["manual_verification_required"]
    assert not refs["compliance_assessed"]
    (order,) = [ref for ref in refs["references"] if ref["document"] == "order_117"]
    assert order["clause"] == {"paragraph": 63, "letter": "б"}
    assert order["strength"] == "related"
