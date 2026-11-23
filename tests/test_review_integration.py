"""Cross-surface acceptance on small authored configurations."""

from __future__ import annotations

import json
from pathlib import Path

from fstec_lint.cli import main


def _text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def test_indeterminate_keeps_known_signals_and_is_not_clean(tmp_path, capsys):
    cfg = tmp_path / "compose.yaml"
    _text(
        cfg,
        "services:\n  known: {image: alpine:3.21, privileged: true}\n"
        "  unresolved: {image: alpine:3.21, privileged: '${RUNTIME_FLAG}'}\n",
    )
    assert (
        main(
            [
                str(cfg),
                "--select",
                "C002",
                "--format",
                "json-context",
                "--strict-scope",
                "--fail-on",
                "none",
            ]
        )
        == 3
    )
    obj = json.loads(capsys.readouterr().out)
    assert obj["partial"]
    assert [x["location"] for x in obj["findings"]] == ["service:known"]
    assert obj["coverage"]["rules"]["C002"]["indeterminate"] == 1
    assert obj["errors"][0]["reason"] == "unresolved_value"
    assert obj["errors"][0]["subjects"] == ["unresolved"]


def test_gis_class_explains_enhancement_without_filtering(tmp_path, capsys):
    cfg = tmp_path / "compose.yaml"
    _text(cfg, "services:\n  sample: {image: alpine:3.21, pid: host}\n")
    data = []
    for extra in ([], ["--gis-class", "1"], ["--gis-class", "3"]):
        assert (
            main([str(cfg), "--select", "C018", "--format", "sarif", "--fail-on", "none", *extra])
            == 0
        )
        out = json.loads(capsys.readouterr().out)["runs"][0]
        descriptor = out["tool"]["driver"]["rules"][0]
        regulatory = descriptor["properties"]["regulatory"]
        (ref,) = [r for r in regulatory["references"] if r["document"] == "methodology_2026_04_12"]
        assert not regulatory["compliance_assessed"]
        data.append([out["results"][0], ref["class_criterion"]])
    assert data[0][0] == data[1][0] == data[2][0]
    assert [x[1] for x in data] == [
        "not_determined",
        "declared_class_matches",
        "declared_class_does_not_match",
    ]


def test_sqlite_does_not_resolve_indeterminate_configuration(tmp_path, capsys):
    conf = tmp_path / "compose.yaml"
    db = tmp_path / "history.sqlite"
    args = [
        str(conf),
        "--select",
        "C009",
        "--strict-scope",
        "--fail-on",
        "none",
        "--format",
        "json",
        "--history-db",
        str(db),
        "--project",
        "demo",
    ]
    _text(conf, "services:\n  app: {image: alpine:3.21, read_only: false}\n")
    assert main([*args, "--revision", "a"]) == 0
    _text(conf, "services:\n  app: {image: alpine:3.21, read_only: '${RUNTIME_FLAG}'}\n")
    assert main([*args, "--revision", "b"]) == 3
    capsys.readouterr()
    assert main(["history", "diff", str(db), "1", "2"]) == 0
    (delta,) = json.loads(capsys.readouterr().out)
    assert (delta["before"], delta["after"], delta["change"]) == ("fail", "unavailable", "unknown")


def test_explicit_overlay_order_and_source_location(tmp_path, capsys):
    base = tmp_path / "compose.yaml"
    overlay = tmp_path / "compose.override.yaml"
    _text(base, "services:\n  app:\n    image: alpine:3.21\n    read_only: false\n")
    _text(overlay, "services:\n  app:\n    read_only: true\n")
    flags = [
        str(tmp_path),
        "--select",
        "C009",
        "--format",
        "json-context",
        "--strict-scope",
        "--fail-on",
        "none",
    ]
    for left, right, found in ((base, overlay, False), (overlay, base, True)):
        assert main([*flags, "--compose-file", left.name, "--compose-file", right.name]) == 0
        report = json.loads(capsys.readouterr().out)
        assert not report["partial"]
        assert bool(report["findings"]) == found
        if found:
            (finding,) = report["findings"]
            assert Path(finding["file"]).name == base.name and finding["line"] == 4


def test_explicit_unsupported_overlay_is_incomplete(tmp_path, capsys):
    for name, alias in (("a.yaml", "first"), ("b.yaml", "second")):
        _text(tmp_path / name, f"services:\n  app:\n    networks: [{alias}]\n")
    assert (
        main(
            [
                str(tmp_path),
                "--compose-file",
                "a.yaml",
                "--compose-file",
                "b.yaml",
                "--select",
                "C018",
                "--format",
                "json-context",
                "--strict-scope",
                "--fail-on",
                "none",
            ]
        )
        == 3
    )
    data = json.loads(capsys.readouterr().out)
    assert data["partial"] and not data["findings"]
    assert data["errors"][0]["reason"] == "compose_merge_unresolved"
