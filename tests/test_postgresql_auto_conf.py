import pytest

from fstec_lint.engine import scan


@pytest.mark.parametrize(
    ("base_value", "auto_value", "expected"),
    [("on", "off", True), ("off", "on", False)],
)
def test_adjacent_auto_is_later_than_explicit_includes(tmp_path, base_value, auto_value, expected):
    main = tmp_path / "postgresql.conf"
    main.write_text("include 'local.conf'\n", encoding="utf-8")
    (tmp_path / "local.conf").write_text(f"ssl={base_value}\n", encoding="utf-8")
    auto = tmp_path / "postgresql.auto.conf"
    auto.write_text(f"# last\nssl={auto_value}\n", encoding="utf-8")
    result = scan(main, select=["P005"], strict_scope=True)
    assert not result.errors
    assert bool(result.findings) is expected
    if expected:
        (finding,) = result.findings
        assert (finding.file, finding.line) == (str(auto), 2)


def test_bad_adjacent_auto_is_not_a_clean_pg_scan(tmp_path):
    main = tmp_path / "postgresql.conf"
    main.write_text("ssl=on\n", encoding="utf-8")
    (tmp_path / "postgresql.auto.conf").write_text("ssl=\n", encoding="utf-8")
    result = scan(main, select=["P005"], strict_scope=True, record_coverage=True)
    assert [error.code for error in result.errors] == ["parse_error"]
    assert result.coverage == {"P005": {"pass": 0, "fail": 0, "unavailable": 1}}


def test_auto_outside_snapshot_is_not_loaded(tmp_path):
    nested = tmp_path / "data"
    nested.mkdir()
    base = nested / "postgresql.conf"
    base.write_text("ssl=on\n", encoding="utf-8")
    (tmp_path / "postgresql.auto.conf").write_text("ssl=off\n", encoding="utf-8")
    result = scan(tmp_path, select=["P005"], strict_scope=True)
    assert not result.errors and not result.findings
