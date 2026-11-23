from pathlib import Path

import pytest

from fstec_lint.engine import scan
from fstec_lint.parsers.compose_merge import ComposeMergeError, parse_compose_files


def put(root: Path, name: str, fields: str) -> Path:
    path = root / name
    path.write_text("services:\n  app:\n" + fields, encoding="utf-8")
    return path


def test_add_ports_with_owner_and_local_suppression(tmp_path: Path) -> None:
    first = put(tmp_path, "base.yml", "    ports: ['5432:5432', '127.0.0.1:27017:27017']\n")
    second = put(
        tmp_path,
        "second.yml",
        "    # fstec-lint: ignore C005\n    ports: [{target: 6379, published: '6380'}]\n",
    )
    third = put(tmp_path, "third.yml", "    ports: ['[::]:9200:9200']\n")
    scan_args = {"select": ["C005"], "strict_scope": True}
    ordering = [first, second, third]
    with_suppression = scan(tmp_path, compose_files=ordering, **scan_args)
    assert not with_suppression.errors
    assert with_suppression.suppressed == 1
    assert {(Path(f.file).name, f.line) for f in with_suppression.findings} == {
        ("base.yml", 3),
        ("third.yml", 3),
    }
    all_entries = scan(tmp_path, compose_files=ordering, inline_exceptions=False, **scan_args)
    assert not all_entries.errors and len(all_entries.findings) == 3
    assert any(Path(f.file).name == "second.yml" and f.line == 4 for f in all_entries.findings)


def test_environment_merge_drops_overridden_findings_and_preserves_others(tmp_path: Path) -> None:
    first = put(
        tmp_path,
        "base.yml",
        "    environment: {APP_DEBUG: 'true', API_KEY: dummy, DEMO_PASSWORD: dummy}\n",
    )
    second = put(
        tmp_path,
        "override.yml",
        "    environment: [APP_DEBUG=false, API_KEY, EXTRA_DEBUG=true]\n",
    )
    merged = parse_compose_files([first, second], tmp_path)
    assert merged["services"]["app"]["environment"] == {
        "APP_DEBUG": "false",
        "API_KEY": None,
        "DEMO_PASSWORD": "dummy",
        "EXTRA_DEBUG": "true",
    }
    audit = scan(
        tmp_path, compose_files=[first, second], select=["C004", "C014"], strict_scope=True
    )
    assert not audit.errors
    assert {(f.rule.id, Path(f.file).name) for f in audit.findings} == {
        ("C004", "base.yml"),
        ("C014", "override.yml"),
    }


def test_exact_port_repeat_is_not_a_second_finding(tmp_path: Path) -> None:
    first = put(tmp_path, "base.yml", "    ports: ['5432:5432']\n")
    second = put(tmp_path, "override.yml", "    ports: ['5432:5432']\n")
    audit = scan(tmp_path, compose_files=[first, second], select=["C005"], strict_scope=True)
    assert not audit.errors
    assert [(Path(f.file).name, f.line) for f in audit.findings] == [("base.yml", 3)]


def test_healthcheck_replaces_test_and_tracks_field_provenance(tmp_path: Path) -> None:
    first = put(tmp_path, "base.yml", "    healthcheck: {test: [CMD, ping], timeout: 1s}\n")
    second = put(tmp_path, "disable.yml", "    healthcheck: {test: [NONE]}\n")
    third = put(tmp_path, "interval.yml", "    healthcheck: {interval: 15s}\n")
    ordered = [first, second, third]
    combined = parse_compose_files(ordered, tmp_path)
    assert combined["services"]["app"]["healthcheck"] == {
        "test": ["NONE"],
        "timeout": "1s",
        "interval": "15s",
    }
    audit = scan(tmp_path, compose_files=ordered, select=["C013"], strict_scope=True)
    assert not audit.errors
    assert [(Path(f.file).name, f.line) for f in audit.findings] == [("disable.yml", 3)]
    reverse = scan(tmp_path, compose_files=ordered[::-1], select=["C013"], strict_scope=True)
    assert not reverse.errors and not reverse.findings


def test_relative_scan_root_does_not_prefix_overlay_paths_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    root = Path("demo")
    root.mkdir()
    put(root, "base.yml", "    user: '65534'\n")
    put(root, "override.yml", "    user: root\n")
    audit = scan(root, compose_files=[Path("base.yml"), Path("override.yml")], select=["C001"])
    assert not audit.errors
    assert [Path(f.file).name for f in audit.findings] == ["override.yml"]


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("ports: ['8080:80']", "ports: ['8081-8082:80-81']"),
        ("ports: ['8080:80']", "ports: [{target: 80, published: 8080, name: http}]"),
        ("ports: ['8080:80']", "ports: ['0.0.0.0:8080:80']"),
        ("environment: {MODE: one}", "environment: [MODE=one, MODE=two]"),
        ("environment: ['MODE=one']", "environment: {MODE: [one]}"),
        ("healthcheck: {test: [CMD, ping]}", "healthcheck: {test: null}"),
    ],
)
def test_unsupported_combinations_keep_scan_partial(
    tmp_path: Path, before: str, after: str
) -> None:
    one = put(tmp_path, "base.yml", f"    {before}\n")
    two = put(tmp_path, "override.yml", f"    {after}\n")
    with pytest.raises(ComposeMergeError):
        parse_compose_files([one, two], tmp_path)
    audit = scan(
        tmp_path, compose_files=[one, two], select=["C005"], strict_scope=True, record_coverage=True
    )
    assert [error.code for error in audit.errors] == ["compose_merge_unresolved"]
    assert audit.coverage == {"C005": {"pass": 0, "fail": 0, "unavailable": 1}}
