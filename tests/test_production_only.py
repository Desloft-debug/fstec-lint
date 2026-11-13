"""Directory-filter behavior through the public interface.

Synthetic configurations use known findings; no discovery implementation is
used to compute expected paths. Default and opt-in scans share the same tree.
"""

import json
from pathlib import Path

import pytest
import yaml

from fstec_lint import engine
from fstec_lint.cli import main
from fstec_lint.engine import discover_files
from fstec_lint.parsers.compose import parse_compose

COMPOSE = "services:\n  db:\n    image: postgres:latest\n    privileged: true\n"
FILTERED = ("test", "tests", "fixture", "fixtures", "example", "examples", "demo", "demos")


def _write(path, text=COMPOSE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _report(root, capsys, *options, production_only=True):
    args = [str(root), "--format", "json", "--fail-on", "none", *options]
    if production_only:
        args.append("--production-only")
    code = main(args)
    captured = capsys.readouterr()
    assert code == 0, captured.err
    return json.loads(captured.out)


@pytest.mark.parametrize("name", FILTERED)
def test_default_preserves_fixture_demo_findings(tmp_path, capsys, name):
    target = _write(tmp_path / name / "docker-compose.yml")
    findings = _report(tmp_path, capsys, "--select", "C002", production_only=False)
    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == target.resolve()
    assert (findings[0]["rule_id"], findings[0]["line"], findings[0]["location"]) == (
        "C002",
        4,
        "service:db",
    )


@pytest.mark.parametrize(
    "filename",
    ["docker-compose.test.yml", "docker-compose.fixtures.yaml", "docker-compose.examples.yml"],
)
def test_production_only_filters_directories_not_filenames(tmp_path, capsys, filename):
    target = _write(tmp_path / "production" / filename)
    findings = _report(tmp_path, capsys, "--select", "C002")
    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == target.resolve()


@pytest.mark.parametrize("name", FILTERED)
@pytest.mark.parametrize("prefix", ["", "deploy/a/b/c"])
def test_production_only_exact_nested_names(tmp_path, monkeypatch, capsys, name, prefix):
    monkeypatch.chdir(tmp_path)
    hidden = _write(tmp_path / prefix / name / "nested/docker-compose.yml")
    kept = _write(tmp_path / "production/docker-compose.yml")
    default = _report(tmp_path, capsys, "--select", "C002", production_only=False)
    assert {f["file"] for f in default} == {
        str(hidden.relative_to(tmp_path)),
        str(kept.relative_to(tmp_path)),
    }
    filtered = _report(tmp_path, capsys, "--select", "C002")
    assert [f["file"] for f in filtered] == [str(Path("production/docker-compose.yml"))]


@pytest.mark.parametrize(
    "name",
    [
        "production",
        "contest",
        "testing",
        "myfixtures",
        "example-prod",
        "demonstration",
        "Test",
        "TESTS",
        "Fixture",
        "FIXTURES",
        "Example",
        "EXAMPLES",
        "Demo",
        "DEMOS",
    ],
)
def test_production_only_preserves_other_names_and_case(tmp_path, capsys, name):
    target = _write(tmp_path / name / "docker-compose.yml")
    findings = _report(tmp_path, capsys, "--select", "C002")
    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == target.resolve()


@pytest.mark.parametrize("external", ["tests", "DEMO", "examples"])
def test_production_only_external_parents_do_not_filter(tmp_path, capsys, external):
    root = tmp_path / external / "selected"
    target = _write(root / "deep/docker-compose.yml")
    findings = _report(root, capsys, "--select", "C002")
    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == target.resolve()


@pytest.mark.parametrize("single_file", [False, True])
@pytest.mark.parametrize("root_name", ["tests", "examples", ".agent-runs"])
def test_production_only_explicit_root_and_file_are_checked(
    tmp_path, capsys, single_file, root_name
):
    root = tmp_path / root_name
    target = _write(root / "docker-compose.yml")
    findings = _report(target if single_file else root, capsys, "--select", "C002")
    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == target.resolve()
    assert findings[0]["line"] == 4
    assert findings[0]["location"] == "service:db"


def test_production_only_exclude_composes_and_preserves_locations(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "examples/docker-compose.yml")
    _write(tmp_path / "deploy/staging/docker-compose.yml")
    _write(tmp_path / "production/docker-compose.yml")
    findings = _report(tmp_path, capsys, "--select", "C002", "--exclude", "deploy/*")
    assert [(f["rule_id"], f["file"], f["line"], f["location"]) for f in findings] == [
        ("C002", str(Path("production/docker-compose.yml")), 4, "service:db")
    ]


@pytest.mark.parametrize("production_only", [False, True])
def test_agent_runs_is_pruned_from_recursive_discovery(tmp_path, capsys, production_only):
    _write(tmp_path / ".agent-runs/run/nested/docker-compose.yml")
    _write(tmp_path / "deploy/.agent-runs/run/compose.yaml", "services: [broken")
    _write(tmp_path / "production/docker-compose.yml")
    findings = _report(tmp_path, capsys, "--select", "C002", production_only=production_only)
    assert len(findings) == 1
    relative = Path(findings[0]["file"]).resolve().relative_to(tmp_path)
    assert relative == Path("production/docker-compose.yml")
    assert ".agent-runs" not in relative.parts


def test_production_only_baseline_roundtrip_preserves_new_findings(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "fixtures/docker-compose.yml")
    _write(tmp_path / "production/docker-compose.yml")
    baseline = tmp_path / "known.json"
    assert (
        main(
            [
                str(tmp_path),
                "--production-only",
                "--select",
                "C002",
                "--write-baseline",
                str(baseline),
            ]
        )
        == 0
    )
    capsys.readouterr()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload == {
        "version": 3,
        "findings": [
            {
                "rule_id": "C002",
                "file": str(Path("production/docker-compose.yml")),
                "location": "service:db",
            }
        ],
    }
    assert _report(tmp_path, capsys, "--select", "C002", "--baseline", str(baseline)) == []
    _write(tmp_path / "new/docker-compose.yml")
    findings = _report(tmp_path, capsys, "--select", "C002", "--baseline", str(baseline))
    assert [f["file"] for f in findings] == [str(Path("new/docker-compose.yml"))]


@pytest.mark.parametrize(
    "filename,kind",
    [
        ("docker-compose.yml", "compose"),
        ("Dockerfile", "dockerfile"),
        ("postgresql.conf", "postgresql_conf"),
        ("pg_hba.conf", "pg_hba"),
        ("sshd_config", "sshd_config"),
        ("app.service", "systemd_unit"),
    ],
)
def test_production_only_discovery_covers_all_file_kinds(tmp_path, filename, kind):
    excluded = _write(tmp_path / "a/tests/deep" / filename, "synthetic data")
    kept = _write(tmp_path / "production/deep" / filename, "synthetic data")
    # Existing optional arguments remain positional; the new mode is opt-in.
    assert set(discover_files(tmp_path, (), None)[kind]) == {excluded, kept}
    discovered = discover_files(tmp_path, (), None, production_only=True)
    assert discovered[kind] == [kept]
    assert sum(map(len, discovered.values())) == 1


@pytest.mark.parametrize("production_only", [False, True])
def test_production_only_single_file_preserves_exclude_contract(tmp_path, capsys, production_only):
    target = _write(tmp_path / "tests/docker-compose.yml")
    findings = _report(
        target, capsys, "--select", "C002", "--exclude", "*", production_only=production_only
    )
    assert len(findings) == 1
    assert Path(findings[0]["file"]).resolve() == target.resolve()


def test_production_only_suppression_select_ignore_and_uz(tmp_path, capsys):
    _write(
        tmp_path / "production/docker-compose.yml",
        COMPOSE.replace("  db:", "  db:  # fstec-lint: ignore C002"),
    )
    findings = _report(tmp_path, capsys, "--select", "C001,C002", "--ignore", "C001")
    assert findings == []
    _write(tmp_path / "production/app.service", "[Service]\nUser=root\nPrivateTmp=no\n")
    findings = _report(tmp_path, capsys, "--select", "U001,U004", "--uz", "4")
    assert [f["rule_id"] for f in findings] == ["U001"]
    assert {f["rule_id"] for f in _report(tmp_path, capsys, "--select", "U001,U004")} == {
        "U001",
        "U004",
    }


@pytest.mark.parametrize(
    "case,expected",
    [
        ("clean", 0),
        ("finding", 1),
        ("missing", 2),
        ("unknown_rule", 2),
        ("malformed", 3),
        ("finding_and_malformed", 1),
        ("excluded_malformed", 0),
    ],
)
def test_production_only_exit_codes(tmp_path, capsys, case, expected):
    root = tmp_path
    options = []
    if case in {"finding", "finding_and_malformed"}:
        _write(root / "production/docker-compose.yml")
    if case in {"malformed", "finding_and_malformed"}:
        _write(root / "production/compose.yaml", "services: [broken")
    if case == "excluded_malformed":
        _write(root / "tests/compose.yaml", "services: [broken")
    if case == "missing":
        root = tmp_path / "absent"
    if case == "unknown_rule":
        options = ["--select", "NO_SUCH_RULE"]
    assert main([str(root), "--production-only", *options]) == expected
    capsys.readouterr()


TEST_SENTINEL = "TEST_SYNTHETIC_PRIVATE_d184"
TEST_FORMATS = ("text", "json", "html", "sarif", "passport")


@pytest.mark.parametrize("fmt", TEST_FORMATS)
@pytest.mark.parametrize("kind", ["syntax", "constructor"])
def test_yaml_diagnostic_preserves_position_without_source(tmp_path, capsys, fmt, kind):
    text = (
        'services:\n  web:\n    image: "' + TEST_SENTINEL + "\n"
        if kind == "syntax"
        else "services:\n  web: !" + TEST_SENTINEL + "\n    image: nginx\n"
    )
    target = _write(tmp_path / "compose.yaml", text)
    # PyYAML itself is the independent position/category oracle; no scanner
    # diagnostic regex, _describe(), or private error constant is reused.
    with pytest.raises(yaml.MarkedYAMLError) as raw:
        yaml.safe_load(text)
    mark = raw.value.problem_mark
    assert mark is not None
    result = engine.scan(tmp_path, select=["C002"])
    assert not result.findings and len(result.errors) == 1
    error = result.errors[0]
    assert Path(error.file) == target
    assert type(raw.value).__name__ in error.message
    assert f"строка {mark.line + 1}, столбец {mark.column + 1}" in error.message
    assert TEST_SENTINEL not in error.message
    assert main([str(tmp_path), "--select", "C002", "--format", fmt, "--fail-on", "none"]) == 3
    captured = capsys.readouterr()
    assert TEST_SENTINEL not in captured.out + captured.err
    assert "Traceback" not in captured.err


def _exception(kind):
    if kind == "unicode":
        return UnicodeDecodeError("utf-8", TEST_SENTINEL.encode(), 0, 1, TEST_SENTINEL)
    if kind == "oserror":
        return OSError(TEST_SENTINEL)
    return ValueError(TEST_SENTINEL + "\ninjected error text")


@pytest.mark.parametrize("fmt", TEST_FORMATS)
@pytest.mark.parametrize("kind", ["value", "unicode", "oserror"])
def test_parser_exception_payload_is_not_diagnostic(tmp_path, monkeypatch, capsys, fmt, kind):
    target = _write(tmp_path / "compose.yaml")

    def failed_parser(_, *, scan_root=None):
        assert scan_root == tmp_path.resolve()
        raise _exception(kind)

    monkeypatch.setattr(engine, "parse_compose", failed_parser)
    result = engine.scan(tmp_path, select=["C002"])
    assert not result.findings and len(result.errors) == 1
    assert Path(result.errors[0].file) == target
    assert type(_exception(kind)).__name__ in result.errors[0].message
    assert TEST_SENTINEL not in result.errors[0].message
    assert main([str(tmp_path), "--select", "C002", "--format", fmt, "--fail-on", "none"]) == 3
    captured = capsys.readouterr()
    assert TEST_SENTINEL not in captured.err + captured.out
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("fmt", TEST_FORMATS)
def test_real_encoding_error_is_controlled(tmp_path, capsys, fmt):
    path = tmp_path / "compose.yaml"
    path.write_bytes(b"# " + TEST_SENTINEL.encode() + b"\nservices: \xff")
    assert main([str(tmp_path), "--select", "C002", "--format", fmt, "--fail-on", "none"]) == 3
    captured = capsys.readouterr()
    assert "UnicodeDecodeError" in captured.err
    assert TEST_SENTINEL not in captured.out + captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("fmt", TEST_FORMATS)
@pytest.mark.parametrize("threshold,expected", [("none", 3), ("high", 1)])
def test_check_error_redaction_preserves_other_findings_and_codes(
    tmp_path, monkeypatch, capsys, fmt, threshold, expected
):
    target = _write(tmp_path / "compose.yaml")

    def failed_check(_):
        raise ValueError(TEST_SENTINEL)

    monkeypatch.setitem(engine.compose_checks.REGISTRY, "C002", failed_check)
    result = engine.scan(tmp_path, select=["C001", "C002"])
    assert [f.rule.id for f in result.findings] == ["C001"]
    finding = result.findings[0]
    assert (Path(finding.file), finding.line, finding.location) == (target, 2, "service:db")
    assert len(result.errors) == 1 and "C002" in result.errors[0].message
    assert TEST_SENTINEL not in result.errors[0].message
    assert (
        main([str(tmp_path), "--select", "C001,C002", "--format", fmt, "--fail-on", threshold])
        == expected
    )
    captured = capsys.readouterr()
    assert "C001" in captured.out
    assert TEST_SENTINEL not in captured.out + captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("kind", ["prefix", "suffix", "subclass"])
def test_legacy_error_lookalike_cannot_echo_payload(tmp_path, monkeypatch, capsys, kind):
    path = _write(tmp_path / "compose.yaml", "web:\n  image: nginx\n")
    with pytest.raises(ValueError) as actual_legacy:
        parse_compose(path)
    known_text = str(actual_legacy.value)

    class LegacyLookalike(ValueError):
        pass

    def failed_parser(_, *, scan_root=None):
        assert scan_root == tmp_path.resolve()
        if kind == "subclass":
            raise LegacyLookalike(known_text)
        raise ValueError(
            TEST_SENTINEL + known_text if kind == "prefix" else known_text + TEST_SENTINEL
        )

    monkeypatch.setattr(engine, "parse_compose", failed_parser)
    assert main([str(tmp_path), "--select", "C002", "--format", "json"]) == 3
    captured = capsys.readouterr()
    assert TEST_SENTINEL not in captured.out + captured.err
    assert "docker-compose v1" not in captured.err
    assert "Traceback" not in captured.err


def test_genuine_legacy_compose_hint_remains_safe(tmp_path, capsys):
    _write(tmp_path / "compose.yaml", TEST_SENTINEL + ":\n  image: nginx\n")
    assert main([str(tmp_path), "--select", "C002"]) == 3
    captured = capsys.readouterr()
    assert "docker-compose v1" in captured.err
    assert TEST_SENTINEL not in captured.out + captured.err
