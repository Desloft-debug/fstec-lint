"""SEC-F-01: rules must reject unsafe graphs before their consumers run.

Small valid inputs use stock SafeLoader as the semantics oracle. Large inputs
run only in the existing bounded child harness (256 MiB, 15 s, bounded output).
"""

import json
from dataclasses import asdict
from unittest.mock import patch

import pytest
import yaml
from test_yaml_alias_resources import _bounded_python

from fstec_lint.engine import RulesError, load_rules
from fstec_lint.parsers import compose

MARKER = "SYNTHETIC_FINAL_RULE_74ce"
RULE = {
    "id": "C002",
    "title": "synthetic",
    "severity": "high",
    "measure": "synthetic",
    "description": "ordinary description",
    "remediation": "ordinary remediation",
    "target": "compose",
}


def _write(tmp_path, content):
    (tmp_path / "rules.yaml").write_text(content, encoding="utf-8")
    return tmp_path


def _excess(kind):
    start = "- " + json.dumps(RULE)[:-1]
    if kind == "self-cycle":
        return start + ", extra: &a [*a]}\n"
    if kind == "mutual-cycle":
        return start + ", extra: &a [&b [*a]]}\n"
    if kind == "repeated-scalar":
        # Below byte/alias limits, above aggregate expanded work budget.
        return start + ', extra: [&a "' + "ab " * 20000 + '", ' + "*a, " * 40 + "]}\n"
    width, levels = (1, 72) if kind == "effective-depth" else (2, 24)
    lines = [yaml.safe_dump([RULE], sort_keys=False).rstrip(), "  x0: &a0 [leaf]"]
    for index in range(1, levels + 1):
        lines.append(f"  x{index}: &a{index} [" + ", ".join([f"*a{index - 1}"] * width) + "]")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    "kind", ["self-cycle", "mutual-cycle", "effective-depth", "wide-dag", "repeated-scalar"]
)
def test_rules_graph_rejected_before_construction_and_merge(tmp_path, kind):
    directory = _write(tmp_path, _excess(kind))
    consumers = []

    def forbidden(*args, **kwargs):
        consumers.append("reached")
        raise AssertionError("unsafe graph reached consumer")

    # An exception from a consumer can be wrapped as RulesError too; the empty
    # call list independently proves rejection happened BEFORE that consumer.
    with (
        patch.object(compose._BoundedLoader, "construct_document", forbidden),
        patch.object(compose._BoundedLoader, "flatten_mapping", forbidden),
        pytest.raises(RulesError) as caught,
    ):
        load_rules(directory)
    assert MARKER not in str(caught.value) + repr(caught.value)
    assert consumers == [], "guard must run before construction/merge flattening"


@pytest.mark.parametrize("merge", [False, True])
def test_rules_ordinary_alias_semantics_match_stock_loader(tmp_path, merge):
    content = "- &rule " + json.dumps(RULE) + "\n"
    content += '- {<<: *rule, id: C004, title: "other"}\n' if merge else "- *rule\n"
    expected = yaml.safe_load(content)
    actual = load_rules(_write(tmp_path, content))
    assert len(actual) == 2
    for rule, raw in zip(actual, expected, strict=True):
        fields = asdict(rule)
        assert rule.severity.name.lower() == raw["severity"]
        assert {key: fields[key] for key in RULE if key != "severity"} == {
            key: raw[key] for key in RULE if key != "severity"
        }


@pytest.mark.parametrize("surface", ["load_rules", "scan", "cli"])
def test_rules_amplification_is_controlled_in_limited_child(tmp_path, surface):
    rule = {**RULE, "description": "ab " * 200000}
    directory = _write(tmp_path, "- &rule " + json.dumps(rule) + "\n" + "- *rule\n" * 700)
    code, out, err = _bounded_python(
        "from pathlib import Path\n"
        + f"directory = Path({str(directory)!r})\nsurface = {surface!r}\n"
        + """
import contextlib
import io
from unittest.mock import patch
from fstec_lint import cli, engine
original = engine.load_rules
def selected(*args, **kwargs):
    return original(directory)
if surface == 'cli':
    output, errors = io.StringIO(), io.StringIO()
    with (
        patch.object(engine, 'load_rules', selected),
        contextlib.redirect_stdout(output),
        contextlib.redirect_stderr(errors),
    ):
        result = cli.main([str(directory), '--fail-on', 'none'])
    assert result == 2, 'invalid rules must never report CLI success'
    assert errors.getvalue().strip()
    assert 'Traceback' not in errors.getvalue()
    assert 'ab ab ab' not in output.getvalue() + errors.getvalue()
else:
    try:
        if surface == 'scan':
            engine.scan(directory, rules_dir=directory)
        else:
            original(directory)
    except engine.RulesError as error:
        assert 'ab ab ab' not in str(error) + repr(error)
    else:
        raise AssertionError('unsafe graph silently accepted')
print('controlled rules error')
"""
    )
    assert code == 0, (out, err)
    assert out.splitlines() == ["controlled rules error"] and not err


@pytest.mark.parametrize("kind", ["syntax", "severity", "container-field"])
def test_rules_invalid_data_diagnostics_are_private(tmp_path, kind):
    rule = {**RULE, "severity": MARKER} if kind == "severity" else RULE
    if kind == "container-field":
        rule = {**RULE, "description": [MARKER]}
    content = "- [" + MARKER if kind == "syntax" else yaml.safe_dump([rule])
    with pytest.raises(RulesError) as caught:
        load_rules(_write(tmp_path, content))
    assert str(caught.value).strip()
    assert MARKER not in str(caught.value) + repr(caught.value)
