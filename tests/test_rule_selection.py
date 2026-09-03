"""Отключение правил: --select/--ignore и подавление комментарием в файле."""

from fstec_lint.cli import main
from fstec_lint.engine import filter_rules, inline_suppressions, load_rules, scan, unknown_patterns

COMPOSE = """services:
  db:
    image: postgres:latest
    privileged: true
"""


def _write(tmp_path, text=COMPOSE, name="docker-compose.yml"):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_filter_rules_select_and_ignore():
    rules = load_rules()

    assert {r.id for r in filter_rules(rules, select=["C001"])} == {"C001"}
    assert {r.id for r in filter_rules(rules, select=["S0*"])} == {
        "S001",
        "S002",
        "S003",
        "S004",
        "S005",
        "S006",
    }
    assert "C001" not in {r.id for r in filter_rules(rules, ignore=["c001"])}


def test_ignore_applies_after_select():
    rules = filter_rules(load_rules(), select=["C0*"], ignore=["C001"])
    ids = {r.id for r in rules}

    assert "C002" in ids
    assert "C001" not in ids


def test_unknown_patterns_are_reported():
    rules = load_rules()

    assert unknown_patterns(rules, ["C001", "XYZ9", "Z*"]) == ["XYZ9", "Z*"]


def test_scan_honours_select_and_ignore(tmp_path):
    _write(tmp_path)

    assert {f.rule.id for f in scan(tmp_path, select=["C002"]).findings} == {"C002"}
    assert "C002" not in {f.rule.id for f in scan(tmp_path, ignore=["C002"]).findings}


def test_inline_comment_suppresses_named_rules(tmp_path):
    _write(
        tmp_path,
        """services:
  db:  # fstec-lint: ignore C001, C009
    image: postgres:latest
    privileged: true
""",
    )

    result = scan(tmp_path)
    ids = {f.rule.id for f in result.findings}

    assert result.suppressed == 2
    assert {"C001", "C009"}.isdisjoint(ids)
    assert "C002" in ids, "подавление именованных правил не должно глушить остальные"


def test_inline_comment_on_previous_line_works(tmp_path):
    _write(
        tmp_path,
        """services:
  # fstec-lint: ignore C002
  db:
    image: postgres:latest
    privileged: true
""",
    )

    assert "C002" not in {f.rule.id for f in scan(tmp_path).findings}


def test_bare_inline_comment_suppresses_everything_on_the_line(tmp_path):
    _write(
        tmp_path,
        """services:
  db:  # fstec-lint: ignore
    image: postgres:latest
    privileged: true
""",
    )

    assert scan(tmp_path).findings == []


def test_inline_comment_accepts_globs(tmp_path):
    _write(
        tmp_path,
        """services:
  db:  # fstec-lint: ignore C0*
    image: postgres:latest
    privileged: true
""",
    )

    assert scan(tmp_path).findings == []


def test_suppression_map_covers_own_and_next_line(tmp_path):
    path = tmp_path / "docker-compose.yml"
    path.write_text("a\n# fstec-lint: ignore C001\nb\n", encoding="utf-8")

    suppressions = inline_suppressions(path)

    assert set(suppressions) == {2, 3}
    assert suppressions[3] == {"C001"}


def test_cli_reports_suppressed_and_unknown_patterns(tmp_path, capsys):
    _write(
        tmp_path,
        """services:
  db:  # fstec-lint: ignore C002
    image: postgres:latest
    privileged: true
""",
    )

    main([str(tmp_path), "--fail-on", "none", "--ignore", "НЕТ-ТАКОГО"])

    err = capsys.readouterr().err
    assert "подавлено комментариями в файлах: 1" in err
    assert "--ignore НЕТ-ТАКОГО — нет правил с таким id" in err
