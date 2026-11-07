"""Small bounded resource fixtures, never OOM/benchmark shell payloads.

Proposed acceptance envelopes for S06/S07: YAML and baseline <=8 MiB,
depth <=64, YAML aliases <=1024, expanded merge pairs <=65536; baseline
<=10000 entries and scalar fields <=65536 chars. Owners may ratify/tighten
these documented policy inputs; this file does not copy a parser algorithm.
"""

import json
from pathlib import Path

import pytest

from fstec_lint import baseline
from fstec_lint.cli import main
from fstec_lint.engine import scan
from fstec_lint.parsers.compose import parse_compose

MARKER = "SYNTHETIC_S02_RESOURCE_643b"
MAX_BYTES = 8 * 1024 * 1024
VALID_COMPOSE = "services:\n  app:\n    privileged: true\n"


def _yaml_depth(depth):
    return "x-nested: " + "[" * depth + json.dumps(MARKER) + "]" * depth + "\n" + VALID_COMPOSE


def _yaml_aliases(count):
    return (
        "x-value: &value [synthetic]\nx-refs: ["
        + ",".join(["*value"] * count)
        + "]\n"
        + VALID_COMPOSE
    )


def _yaml_merge(levels):
    # Each merge multiplies pairs before duplicate-key collapse in SafeLoader.
    # 4**9 = 262144 pairs is bounded; source is under 1 KiB.
    lines = ["x-base: &base {key: " + MARKER + "}"]
    previous = "base"
    for level in range(levels):
        name = f"m{level}"
        refs = ", ".join(["*" + previous] * 4)
        lines.append(f"x-{name}: &{name} {{<<: [{refs}]}}")
        previous = name
    return "\n".join(lines) + "\n" + VALID_COMPOSE


@pytest.mark.parametrize("kind", ["bytes", "depth", "aliases", "merge"])
def test_s02_yaml_resource_excess_is_controlled_error(tmp_path, capsys, kind):
    content = {
        "bytes": lambda: VALID_COMPOSE + "#" + "x" * MAX_BYTES + MARKER,
        "depth": lambda: _yaml_depth(128),
        "aliases": lambda: _yaml_aliases(2048),
        "merge": lambda: _yaml_merge(9),
    }[kind]()
    path = tmp_path / "compose.yaml"
    path.write_bytes(content.encode("utf-8"))
    result = scan(path, select=["C002"])
    assert len(result.errors) == 1 and result.errors[0].file == str(path)
    assert result.findings == []
    assert MARKER not in repr(result.errors)
    assert main([str(path), "--select", "C002", "--fail-on", "none"]) == 3
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert MARKER not in captured.err + captured.out
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("kind", ["bytes", "depth", "aliases", "merge"])
def test_s02_yaml_valid_envelope_keeps_detection(tmp_path, kind):
    content = {
        "bytes": lambda: VALID_COMPOSE + "#" + "x" * (MAX_BYTES - len(VALID_COMPOSE) - 1),
        "depth": lambda: _yaml_depth(32),
        "aliases": lambda: _yaml_aliases(32),
        "merge": lambda: _yaml_merge(3),
    }[kind]()
    path = tmp_path / "compose.yaml"
    path.write_bytes(content.encode("utf-8"))
    result = scan(path, select=["C002"])
    assert result.errors == []
    assert len(result.findings) == 1 and result.findings[0].rule.id == "C002"
    expected_line = content.splitlines().index("    privileged: true") + 1
    assert (result.findings[0].file, result.findings[0].line) == (str(path), expected_line)


def test_s02_yaml_oversize_rejected_before_full_text_read(tmp_path, monkeypatch):
    path = tmp_path / "compose.yaml"
    path.write_bytes(b"#" + b"x" * MAX_BYTES)
    original = Path.read_text
    reads = []

    def observed(file, *args, **kwargs):
        if file == path:
            reads.append(file)
        return original(file, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", observed)
    with pytest.raises(ValueError):
        parse_compose(path)
    assert reads == [], "the existing limit is currently checked after allocation"


def _entry(index=0, location="service:app"):
    return {"rule_id": "C002", "file": f"app-{index}/compose.yaml", "location": location}


def _baseline_content(kind, excessive):
    payload = {"version": 3, "findings": [_entry()]}
    if kind == "entries":
        payload["findings"] = [_entry(i) for i in range(10001 if excessive else 10000)]
    elif kind == "scalar":
        payload["findings"] = [_entry(location="s" * (65537 if excessive else 65536))]
    elif kind == "depth":
        depth = 128 if excessive else 16
        # An unrelated extension must still have bounded parsing cost.
        return (
            '{"version":3,"findings":[],"extension":'
            + "[" * depth
            + json.dumps(MARKER)
            + "]" * depth
            + "}"
        )
    raw = json.dumps(payload)
    if kind == "bytes":
        raw += " " * (MAX_BYTES + (1 if excessive else 0) - len(raw.encode("utf-8")))
    return raw


@pytest.mark.parametrize("kind", ["bytes", "depth", "entries", "scalar"])
def test_s02_baseline_resource_excess_is_safe_usage_error(tmp_path, capsys, kind):
    saved = tmp_path / "resource.json"
    saved.write_bytes(_baseline_content(kind, True).encode("utf-8"))
    original = saved.read_bytes()
    with pytest.raises(baseline.BaselineError) as caught:
        baseline.load(saved)
    assert MARKER not in str(caught.value) + repr(caught.value)
    assert main([str(tmp_path), "--baseline", str(saved), "--fail-on", "none"]) == 2
    captured = capsys.readouterr()
    assert captured.err.strip() and "Traceback" not in captured.err
    assert MARKER not in captured.err + captured.out
    assert saved.read_bytes() == original


@pytest.mark.parametrize("kind", ["bytes", "depth", "entries", "scalar"])
def test_s02_baseline_valid_envelope_remains_readable(tmp_path, kind):
    saved = tmp_path / "valid.json"
    saved.write_bytes(_baseline_content(kind, False).encode("utf-8"))
    original = saved.read_bytes()
    known = baseline.load(saved)
    expected_count = {"bytes": 1, "depth": 0, "entries": 10000, "scalar": 1}[kind]
    assert len(known) == expected_count
    if kind == "bytes":
        assert known == {"C002|app-0/compose.yaml|service:app"}
    assert saved.read_bytes() == original
