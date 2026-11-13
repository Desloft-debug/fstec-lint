"""Typed standalone Compose tags under the NEW bounded loader.

Oracle: https://docs.docker.com/reference/compose-file/merge/ (reset/replace).
These tests specify standalone analysis; they do not assert multi-file merging.
"""

import pytest
import yaml
from integration_helpers import write

from fstec_lint.engine import scan
from fstec_lint.parsers import compose as parser


@pytest.mark.parametrize(
    "value", ["true", "false", "1", '"true"', "null", "[SYS_ADMIN]", "{PASSWORD: synthetic}"]
)
def test_override_preserves_stock_yaml_types(tmp_path, value):
    # The oracle runs an isolated stock parser on tiny, tag-free YAML only.
    content = f"services: {{app: {{x-value: !override {value}}}}}\n"
    parsed = parser.parse_compose(write(tmp_path / "compose.yaml", content))
    expected = yaml.safe_load(value)
    actual = parsed["services"]["app"]["x-value"]
    assert actual == expected and type(actual) is type(expected)


@pytest.mark.parametrize(
    "body,rule,reported",
    [
        ("privileged: !override true", "C002", True),
        ("privileged: !override false", "C002", False),
        ("cap_drop: [ALL]\ncap_add: !override [SYS_ADMIN]", "C003", True),
        ("environment: !override {PASSWORD: SYNTHETIC_TEST_TAG_SECRET}", "C004", True),
        ("privileged: !reset true", "C002", False),
        ("cap_drop: [ALL]\ncap_add: !reset [SYS_ADMIN]", "C003", False),
        ("environment: !reset {PASSWORD: SYNTHETIC_TEST_TAG_SECRET}", "C004", False),
        ("cap_drop: !reset [ALL]", "C003", True),
    ],
)
def test_single_file_effective_tag_policy(tmp_path, body, rule, reported):
    path = write(
        tmp_path / "compose.yaml", "services:\n  app:\n    " + body.replace("\n", "\n    ") + "\n"
    )
    result = scan(path, select=[rule])
    assert not result.errors and bool(result.findings) is reported
    assert "SYNTHETIC_TEST_TAG_SECRET" not in repr(result.findings) + repr(result.errors)


@pytest.mark.parametrize("tag", ["!reset", "!override"])
@pytest.mark.parametrize("budget", ["size", "aliases", "nodes", "depth", "graph", "merges"])
def test_tag_limits_run_before_construction(tmp_path, monkeypatch, tag, budget):
    contents = {
        "size": ("MAX_FILE_BYTES", 32, f"services: {{app: {{x: {tag} {'x' * 100}}}}}\n"),
        "aliases": (
            "MAX_YAML_ALIASES",
            1,
            f"x: &a [leaf]\nservices: {{app: {{x: {tag} [*a, *a]}}}}\n",
        ),
        "nodes": ("MAX_YAML_NODES", 3, f"services: {{app: {{x: {tag} [a,b,c]}}}}\n"),
        "depth": ("MAX_YAML_DEPTH", 3, f"services: {{app: {{x: {tag} [[[leaf]]]}}}}\n"),
        "graph": (
            "MAX_YAML_EXPANDED_COST",
            200,
            f"x: &a [leaf]\nservices: {{app: {{x: {tag} [*a,*a]}}}}\n",
        ),
        "merges": (
            "MAX_MERGE_WORK",
            1,
            f"x: &a {{one: 1, two: 2}}\nservices: {{app: {tag} {{<<: *a}}}}\n",
        ),
    }
    constant, limit, content = contents[budget]
    monkeypatch.setattr(parser, constant, limit)
    reached = []

    def forbidden(*args, **kwargs):
        reached.append(True)
        raise AssertionError("construction happened before budget validation")

    monkeypatch.setattr(parser._BoundedLoader, "construct_document", forbidden)
    with pytest.raises(ValueError):
        parser.parse_compose(write(tmp_path / "compose.yaml", content))
    assert not reached


@pytest.mark.parametrize("tag", ["!reset", "!override"])
def test_tagged_cycles_are_rejected_before_construction(tmp_path, monkeypatch, tag):
    called = []

    def forbidden(*args, **kwargs):
        called.append(True)
        raise AssertionError("cycle reached construction")

    monkeypatch.setattr(parser._BoundedLoader, "construct_document", forbidden)
    path = write(tmp_path / "compose.yaml", f"x: &a {tag} [*a]\nservices: {{}}\n")
    with pytest.raises(ValueError):
        parser.parse_compose(path)
    assert not called
