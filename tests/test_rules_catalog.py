import json

from fstec_lint.cli import main
from fstec_lint.engine import load_rules
from fstec_lint.models import Rule, Severity
from fstec_lint.reporters import rules_catalog


def _rule(rule_id="X001", measure="п. 63 д)", target="compose"):
    return Rule(
        id=rule_id,
        title="Тестовое правило",
        severity=Severity.HIGH,
        measure=measure,
        measure_title="Защита технологий контейнерных сред и их оркестрации",
        description="описание",
        remediation="исправление",
        target=target,
        orders="Приказ ФСТЭК №117",
    )


def test_measure_groups_reads_clauses_of_order_117():
    """Покрытие считается по пунктам приказа N 117, а не по кодам N 17."""
    assert rules_catalog.measure_groups(_rule(measure="п. 63 д)")) == ["п. 63 д)"]
    assert rules_catalog.measure_groups(_rule(measure="п. 34 б)")) == ["п. 34 б)"]


def test_render_text_lists_every_rule():
    rules = load_rules()
    output = rules_catalog.render_text(rules)
    assert f"Правил всего: {len(rules)}" in output
    for rule in rules:
        assert rule.id in output
    assert "Затронутые пункты приказа ФСТЭК N 117:" in output


def test_render_json_shape():
    rules = load_rules()
    payload = json.loads(rules_catalog.render_json(rules))
    assert payload["total"] == len(rules)
    assert len(payload["rules"]) == len(rules)
    assert payload["measure_groups"]
    first = payload["rules"][0]
    assert {"id", "severity", "target", "measure_groups", "orders"} <= set(first)


def test_cli_list_rules_text(capsys):
    assert main(["--list-rules"]) == 0
    out = capsys.readouterr().out
    assert "Правил всего:" in out
    assert "C002" in out


def test_cli_list_rules_json(capsys):
    assert main(["--list-rules", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == len(load_rules())


def test_cli_list_rules_ignores_scan_path(tmp_path, capsys):
    # каталог правил не зависит от сканируемого пути и не падает на пустом
    assert main(["--list-rules", str(tmp_path)]) == 0
    assert "Правил всего:" in capsys.readouterr().out
