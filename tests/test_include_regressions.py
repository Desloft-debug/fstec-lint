import pytest

from fstec_lint.engine import scan


def test_postgres_suppression_quoted_escape_and_real_comment(tmp_path):
    main = tmp_path / "postgresql.conf"
    main.write_text(
        "log_line_prefix = 'prefix ''quoted'' # fstec-lint: ignore P005'\nssl=off\n",
        encoding="utf-8",
    )
    result = scan(main, select=["P005"])
    assert not result.errors and len(result.findings) == 1 and result.suppressed == 0
    main.write_text("ssl=off # fstec-lint: ignore P005\n", encoding="utf-8")
    result = scan(main, select=["P005"])
    assert not result.errors and not result.findings and result.suppressed == 1


def test_postgres_include_dir_symlinks_last_name_wins(tmp_path):
    parts = tmp_path / "parts"
    parts.mkdir()
    values = tmp_path / "values"
    values.mkdir()
    (values / "z.txt").write_text("ssl=on\n", encoding="utf-8")
    late = values / "a.txt"
    late.write_text("ssl=off\n", encoding="utf-8")
    try:
        (parts / "10.conf").symlink_to(values / "z.txt")
        (parts / "20.conf").symlink_to(late)
    except OSError as exc:
        pytest.skip(f"Symlink creation unavailable: {exc!r}")
    main = tmp_path / "postgresql.conf"
    main.write_text("include_dir 'parts'\n", encoding="utf-8")
    result = scan(main, select=["P005"])
    assert not result.errors
    assert [(f.file, f.line) for f in result.findings] == [(str(late), 1)]
