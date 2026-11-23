from pathlib import Path

import pytest

from fstec_lint.checks.compose_checks import REGISTRY
from fstec_lint.parsers.base import SourceLine
from fstec_lint.parsers.compose import parse_compose
from fstec_lint.parsers.compose_merge import (
    MAX_OVERLAY_FILES,
    ComposeMergeError,
    MergedComposeFile,
    parse_compose_files,
)


def put(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.write_text(text, encoding="utf-8")
    return path


def test_merge_scalars_and_preserve_field_provenance(tmp_path: Path) -> None:
    base = put(
        tmp_path,
        "compose.yml",
        "services:\n  demo:\n    image: alpine:3.21\n    read_only: true\n",
    )
    overlay = put(
        tmp_path,
        "custom.yml",
        "services:\n  demo:\n    read_only: false\n    user: '1000'\n",
    )

    merged = parse_compose_files([Path(base.name), overlay], tmp_path)
    assert isinstance(merged, MergedComposeFile)
    assert merged["services"]["demo"] == {
        "image": "alpine:3.21",
        "read_only": False,
        "user": "1000",
    }
    image = merged.key_line("demo", "image")
    assert isinstance(image, SourceLine) and image.file == str(base.resolve()) and image == 3
    line = merged.key_line("demo", "read_only")
    assert isinstance(line, SourceLine) and line.file == str(overlay.resolve()) and line == 3
    assert merged.suppression_lines("demo", line) == (2, 3)
    finding = REGISTRY["C009"](merged)[0]
    assert getattr(finding[2], "file", None) == str(overlay.resolve())

    reversed_layers = parse_compose_files([overlay, base], tmp_path)
    assert reversed_layers["services"]["demo"]["read_only"] is True
    assert REGISTRY["C009"](reversed_layers) == []


def test_merge_add_disjoint_services_and_top_level_resources(tmp_path: Path) -> None:
    base = put(
        tmp_path, "compose.yml", "services: {base: {image: alpine:3.21}}\nvolumes: {one: {}}\n"
    )
    override = put(
        tmp_path, "override.yml", "services: {demo: {image: alpine:3.21}}\nvolumes: {two: {}}\n"
    )
    result = parse_compose_files([base, override], tmp_path)
    assert set(result["services"]) == {"base", "demo"}
    assert result["volumes"] == {"one": {}, "two": {}}


@pytest.mark.parametrize(
    ("one", "two"),
    (
        ("ports: ['127.0.0.1:81:80']", "ports: ['127.0.0.1:82:80']"),
        ("healthcheck: {test: ['CMD', 'true']}", "healthcheck: {timeout: '1s'}"),
        ("environment: {APP_MODE: demo}", "environment: ['APP_MODE=test']"),
        ("read_only: true", "read_only: null"),
    ),
)
def test_merge_nontrivial_conflicts_are_refused(tmp_path: Path, one: str, two: str) -> None:
    base = put(tmp_path, "first.yml", f"services:\n  demo:\n    {one}\n")
    overlay = put(tmp_path, "second.yml", f"services:\n  demo:\n    {two}\n")
    with pytest.raises(ComposeMergeError, match="повтор поля"):
        parse_compose_files([base, overlay], tmp_path)


@pytest.mark.parametrize(
    "text",
    (
        "services: {demo: {read_only: !reset false}}",
        "services: {demo: {read_only: !override true}}",
        "services: {demo: {read_only: '${DEMO_SETTING}'}}",
        "services: {first: &defaults {read_only: true}, demo: *defaults}",
        "include: [local-demo.yml]",
    ),
)
def test_merge_refuses_directives_that_need_full_compose_semantics(
    tmp_path: Path, text: str
) -> None:
    base = put(tmp_path, "base.yml", "services: {demo: {image: alpine:3.21}}")
    overlay = put(tmp_path, "overlay.yml", text)
    with pytest.raises(ValueError):
        parse_compose_files([base, overlay], tmp_path)


def test_overlay_constraints_do_not_change_single_file_parser(tmp_path: Path) -> None:
    base = put(tmp_path, "base.yml", "services: {demo: {read_only: '${DEMO_SETTING}'}}")
    assert parse_compose(base)["services"]["demo"]["read_only"] == "${DEMO_SETTING}"


def test_merge_paths_and_file_count_must_be_bounded(tmp_path: Path) -> None:
    base = put(tmp_path, "base.yml", "services: {demo: {image: alpine:3.21}}")
    with pytest.raises(ComposeMergeError, match="за границей"):
        parse_compose_files([base, Path("../outside.yml")], tmp_path)
    with pytest.raises(ComposeMergeError, match="различными"):
        parse_compose_files([base, Path("base.yml")], tmp_path)
    with pytest.raises(ComposeMergeError, match="файлов"):
        parse_compose_files([base] * (MAX_OVERLAY_FILES + 1), tmp_path)


def test_merge_budget_is_shared_between_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fstec_lint.parsers.compose_merge as parser

    base = put(tmp_path, "first.yml", "services: {first: {image: alpine:3.21}}")
    overlay = put(tmp_path, "second.yml", "services: {second: {image: alpine:3.21}}")
    monkeypatch.setattr(parser, "MAX_FILE_BYTES", 60)
    with pytest.raises(ValueError, match="resource limit"):
        parse_compose_files([base, overlay], tmp_path)
