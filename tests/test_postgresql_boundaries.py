"""QA boundaries for the documented Include and suppression contracts."""

import json

import pytest
from integration_helpers import cli, write

from fstec_lint.engine import scan


@pytest.mark.parametrize("included", [False, True])
@pytest.mark.parametrize("real_comment", [False, True])
def test_postgres_suppression_requires_comment(tmp_path, included, real_comment):
    main = tmp_path / "postgresql.conf"
    origin = tmp_path / "parts/value.conf" if included else main
    marker = "# fstec-lint: ignore P005"
    prefix = marker if real_comment else f"log_line_prefix = '{marker}'"
    write(origin, prefix + "\nssl=off\n")
    if included:
        write(main, "include 'parts/value.conf'\n")
    result = scan(main, select=["P005"])
    assert not result.errors
    assert len(result.findings) == (0 if real_comment else 1)
    if not real_comment:
        assert (result.findings[0].file, result.findings[0].line) == (str(origin), 2)


def test_postgres_nested_relative_origin_and_override(tmp_path):
    main = write(tmp_path / "postgresql.conf", "ssl=on\ninclude 'parts/a.conf'\n")
    write(tmp_path / "parts/a.conf", "include '../values/b.conf'\n")
    origin = write(tmp_path / "values/b.conf", "# origin\nssl=off\n")
    result = scan(main, select=["P005"])
    assert not result.errors and len(result.findings) == 1
    assert (result.findings[0].file, result.findings[0].line) == (str(origin), 2)
    main.write_text("include 'parts/a.conf'\nssl=on\n", encoding="utf-8")
    assert not scan(main, select=["P005"]).findings


@pytest.mark.parametrize("name", [".hidden.conf", "ignored.txt", "ignored.conf.bak"])
def test_postgres_include_dir_ignores_unselected_files(tmp_path, name):
    main = write(tmp_path / "postgresql.conf", "ssl=on\ninclude_dir 'parts'\n")
    write(tmp_path / "parts/10.conf", "ssl=on\n")
    write(tmp_path / "parts" / name, "ssl=off\n")
    result = scan(main, select=["P005"])
    assert not result.errors and not result.findings


def test_postgres_include_dir_ignores_subdirectories(tmp_path):
    main = write(tmp_path / "postgresql.conf", "ssl=on\ninclude_dir 'parts'\n")
    write(tmp_path / "parts/10.conf", "ssl=on\n")
    (tmp_path / "parts/sub.conf").mkdir()
    result = scan(main, select=["P005"])
    assert not result.errors and not result.findings


def link_or_skip(path, target):
    try:
        path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"Symlink creation unavailable: {exc!r}")


def test_postgres_include_dir_orders_entry_names_not_resolved_targets(tmp_path):
    main = write(tmp_path / "postgresql.conf", "include_dir 'parts'\n")
    early = write(tmp_path / "values/z.txt", "ssl=off\n")
    late = write(tmp_path / "values/a.txt", "ssl=on\n")
    (tmp_path / "parts").mkdir()
    link_or_skip(tmp_path / "parts/10.conf", early)
    link_or_skip(tmp_path / "parts/20.conf", late)
    result = scan(main, select=["P005"])
    assert not result.errors and not result.findings


@pytest.mark.parametrize("optional", [False, True])
def test_postgres_include_symlink_outside_is_private_error(tmp_path, capsys, optional):
    secret = "TEST_SYNTHETIC_SECRET_c91a"
    outside = write(tmp_path / "outside.conf", "ssl=off\n# " + secret)
    root = tmp_path / "selected"
    main = write(root / "postgresql.conf", "ssl=on\n")
    link_or_skip(root / "linked.conf", outside)
    directive = "include_if_exists" if optional else "include"
    main.write_text(directive + " 'linked.conf'\n", encoding="utf-8")
    assert cli([str(main), "--select", "P005", "--format", "json"]) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert secret not in captured.out + captured.err and "Traceback" not in captured.err


@pytest.mark.parametrize("depth", [15, 16])
def test_postgres_include_depth_limit(tmp_path, depth):
    main = write(tmp_path / "postgresql.conf", "include 'f1.conf'\n")
    for index in range(1, depth + 1):
        write(
            tmp_path / f"f{index}.conf",
            f"include 'f{index + 1}.conf'\n" if index < depth else "ssl=on\n",
        )
    result = scan(main, select=["P005"])
    assert bool(result.errors) is (depth == 16)


@pytest.mark.parametrize("count", [255, 256])
def test_postgres_include_file_budget(tmp_path, count):
    main = write(tmp_path / "postgresql.conf", "include 'child.conf'\n" * count)
    write(tmp_path / "child.conf", "ssl=on\n")
    result = scan(main, select=["P005"])
    assert bool(result.errors) is (count == 256)


@pytest.mark.parametrize(
    "body", ["include unquoted", "include 'missing.conf'", "include_dir 'missing'"]
)
def test_postgres_include_errors_hide_values(tmp_path, capsys, body):
    secret = "TEST_SYNTHETIC_SECRET_c91a"
    main = write(tmp_path / "postgresql.conf", body + " # " + secret)
    assert cli([str(main), "--select", "P005", "--format", "json"]) == 3
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err and "Traceback" not in captured.err


def test_compose_pair_reports_partial_without_false_clean(tmp_path, capsys):
    write(tmp_path / "compose.yaml", "services: {app: {privileged: false}}\n")
    write(tmp_path / "compose.override.yaml", "services: {app: {privileged: false}}\n")
    assert cli([str(tmp_path), "--select", "C002", "--format", "json"]) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out) == [] and captured.err
    assert cli([str(tmp_path / "compose.yaml"), "--select", "C002"]) == 0
