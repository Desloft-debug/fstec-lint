from __future__ import annotations

import json

import pytest

from fstec_lint import kzi, regulatory
from fstec_lint.engine import load_rules
from fstec_lint.reporters.rules_catalog import render_json, render_text


@pytest.fixture(scope="module")
def catalogue() -> dict:
    return json.loads(render_json(load_rules()))


def by_rule(catalogue: dict, rule_id: str) -> dict:
    return next(row for row in catalogue["rules"] if row["id"] == rule_id)


def references(row: dict, document: str) -> list[dict]:
    return [x for x in row["regulatory"]["references"] if x["document"] == document]


@pytest.mark.parametrize("rule_id", ["C007", "C018", "C019"])
def test_namespace_names_actual_limited_enhancement(catalogue, rule_id):
    row = by_rule(catalogue, rule_id)
    normal, *_ = references(row, "order_117")
    assert normal["clause"] == {"paragraph": 63, "letter": "д"}
    (direct,) = references(row, "methodology_2026_04_12")
    assert direct["clause"] == {"section": "IV", "code": "ЗКО.5", "enhancement": 1}
    assert direct["class_criteria"] == ["К1", "К2"]
    assert direct["strength"] == "direct_signal"
    assert row["regulatory"]["manual_verification_required"] is True


def test_legacy_related_reference_does_not_become_primary(catalogue):
    item = by_rule(catalogue, "C007")
    assert item["measure"] == "п. 63 п)"
    legacy = [r for r in references(item, "order_117") if r["relation"] == "legacy_catalogue"]
    assert legacy[0]["clause"] == {"paragraph": 63, "letter": "п"}
    assert legacy[0]["strength"] == "related"


def test_time_scopes_are_output_without_compliance_claim(catalogue):
    base = references(by_rule(catalogue, "C020"), "order_117")[0]
    assert base["revision"] == "2026-05-08"
    assert base["revision_in_force_from"] == "2026-09-01"
    assert base["revision_exception"] == {"paragraph": 32, "effective_from": "2027-03-01"}
    assert not references(by_rule(catalogue, "C020"), "order_21")
    out = catalogue["regulatory"]
    assert not out["compliance_assessed"]
    assert out["applicability"] == "not_determined"
    assert set(out["observation_states"]) == {"observed", "not_observed", "indeterminate", "manual"}


def test_secret_name_is_only_context_and_auth_trust_is_not_default_password(catalogue):
    for code in ("C004", "D003"):
        refs = references(by_rule(catalogue, code), "methodology_2026_04_12")
        assert refs[0]["strength"] == "related"
    assert "P001" not in kzi.SUPPORTED_INDICATORS["k23"]


def test_legacy_pdn_codes_and_levels_are_additive_and_not_proven(catalogue):
    row = by_rule(catalogue, "P008")
    assert row["pdn_measure"] == "ОДТ.1"
    (pd,) = references(row, "order_21")
    assert pd["clause"]["code"] == "ОДТ.1"
    assert pd["baseline_security_levels"] == []
    assert pd["strength"] == "related"
    assert "class_criteria" not in pd


def test_audited_rows_are_not_compliance_verdicts(catalogue):
    checked = [x for x in catalogue["rules"] if x["regulatory"]["assessed_reference"]]
    assert len(checked) == 32
    for row in catalogue["rules"]:
        md = row["regulatory"]
        assert md["references"] and md["limitation"]
        assert md["applicability"] == "not_determined"
        assert md["compliance_assessed"] is False


def test_context_is_shared_with_text_without_overstating(catalogue):
    assert catalogue["regulatory"] == regulatory.catalogue_context()
    assert "не подтверждают применимость или выполнение мер" in render_text(load_rules())
