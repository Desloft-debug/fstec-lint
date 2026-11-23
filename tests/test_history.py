from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from fstec_lint.cli import main
from fstec_lint.history import HistoryError, Record, compare, list_runs, record_run


def scan(root: Path, db: Path, revision: str, *extra: str) -> int:
    return main(
        [
            str(root),
            "--history-db",
            str(db),
            "--project",
            "sample",
            "--revision",
            revision,
            "--select",
            "D004",
            "--fail-on",
            "low",
            "-f",
            "json",
            *extra,
        ]
    )


def test_history_fix_unknown_and_no_location_leak(tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    db = tmp_path / "history.sqlite3"
    dockerfile = root / "Dockerfile"
    dockerfile.write_text(
        "FROM example.invalid/keep-out-of-history:latest\nRUN printf 'NOT_FOR_HISTORY_32a8'\n",
        encoding="utf8",
    )
    assert scan(root, db, "a", "--run-key", "repeat-a") == 1
    capsys.readouterr()
    assert scan(root, db, "a", "--run-key", "repeat-a") == 1
    assert "уже записан" in capsys.readouterr().err
    dockerfile.write_text("FROM alpine:3.23\n", encoding="utf8")
    assert scan(root, db, "a", "--run-key", "repeat-a") == 2
    assert "другого результата" in capsys.readouterr().err
    assert scan(root, db, "b") == 0
    dockerfile.write_bytes(b"\xff\xfe\xcc")
    assert scan(root, db, "c") == 3
    dockerfile.unlink()
    assert scan(root, db, "d") == 0
    assert [r["checks"] for r in list_runs(db, "sample")] == [1, 1, 1, 0]
    assert compare(db, 1, 2)[0]["change"] == "resolved"
    assert compare(db, 1, 3)[0]["change"] == "unknown"
    assert compare(db, 1, 4)[0]["change"] == "unknown"
    assert compare(db, 2, 1)[0]["change"] == "new"
    assert compare(db, 1, 2)[0]["path"] == "Dockerfile"
    assert b"NOT_FOR_HISTORY_32a8" not in db.read_bytes()
    assert b"keep-out-of-history" not in db.read_bytes()
    assert str(tmp_path).encode() not in db.read_bytes()


def test_baseline_and_inline_do_not_erase_history(tmp_path, capsys):
    cfg = tmp_path / "Dockerfile"
    cfg.write_text("FROM alpine:latest\n", encoding="utf8")
    db = tmp_path / "h.db"
    assert scan(cfg, db, "first") == 1
    baseline = tmp_path / "baseline.json"
    assert main([str(cfg), "--select", "D004", "--write-baseline", str(baseline)]) == 0
    capsys.readouterr()
    assert scan(cfg, db, "baseline", "--baseline", str(baseline)) == 0
    assert json.loads(capsys.readouterr().out) == []
    cfg.write_text("# fstec-lint: ignore D004\nFROM alpine:latest\n", encoding="utf8")
    assert scan(cfg, db, "inline") == 0
    assert compare(db, 1, 2) == compare(db, 1, 3) == []


def test_partial_with_exit_one_is_not_a_completed_run(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM alpine:latest\n")
    db = tmp_path / "history.db"
    assert scan(root, db, "a") == 1
    (root / "Dockerfile").write_text("FROM alpine:3.23\n")
    (root / "Dockerfile.second").write_text("FROM alpine:latest\n")
    (root / "Dockerfile.broken").write_bytes(b"\xff")
    assert scan(root, db, "b") == 1
    assert list_runs(db, "sample")[1]["errors"] == 1
    assert {r["change"] for r in compare(db, 1, 2)} == {"unknown"}


def test_moved_line_is_not_new(tmp_path):
    cfg = tmp_path / "Dockerfile"
    db = tmp_path / "h.db"
    for index in range(2):
        cfg.write_text("\n" * index + "FROM alpine:latest\n")
        assert scan(cfg, db, str(index)) == 1
    assert compare(db, 1, 2) == []


def test_history_is_opt_in(tmp_path):
    cfg = tmp_path / "Dockerfile"
    cfg.write_text("FROM alpine:3.23\n")
    assert main([str(cfg), "--select", "D004"]) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == ["Dockerfile"]


def test_input_and_output_cannot_point_to_db(tmp_path):
    cfg = tmp_path / "Dockerfile"
    cfg.write_text("FROM alpine:3.23\n")
    db = tmp_path / "h.db"
    assert scan(cfg, db, "a") == 0
    old = db.read_bytes()
    assert scan(cfg, db, "b", "--output", str(db)) == 2
    assert (
        main(
            [
                "history",
                "import-junit",
                str(db),
                str(db),
                "--project",
                "sample",
                "--revision",
                "a",
                "--runner-version",
                "1",
                "--profile",
                "unit",
            ]
        )
        == 2
    )
    assert db.read_bytes() == old


def test_existing_foreign_db_not_modified(tmp_path):
    db = tmp_path / "foreign.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE unrelated (id INTEGER)")
    cfg = tmp_path / "Dockerfile"
    cfg.write_text("FROM alpine:3.23\n")
    original = db.read_bytes()
    assert scan(cfg, db, "a") == 2
    assert db.read_bytes() == original


def test_transaction_rollback_and_fk(tmp_path):
    db = tmp_path / "h.db"
    params = dict(
        path=db, project="sample", revision="a", tool="junit", version="0", profile="unit", errors=0
    )
    with pytest.raises(sqlite3.IntegrityError):
        record_run(**params, records=[Record("a", ".", "pass"), Record("bad", ".", "wrong")])
    assert list_runs(db, "sample") == []
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        assert conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO revisions VALUES (1, 99, 'orphan')")
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_quotes_are_data_and_runs_across_projects_not_comparable(tmp_path):
    db = tmp_path / "h.db"
    for name in ("team'a", "team b"):
        record_run(
            db,
            project=name,
            revision="a",
            tool="junit",
            version="0",
            profile="unit",
            errors=0,
            records=[Record("a", ".", "pass")],
        )
    assert len(list_runs(db, "team'a")) == 1
    assert list_runs(db, "other' OR 1=1") == []
    with pytest.raises(HistoryError, match="одного проекта"):
        compare(db, 1, 2)


def test_junit_import_status_no_message_and_trends(tmp_path, capsys):
    db = tmp_path / "h.db"
    report = tmp_path / "report.xml"
    args = [
        "history",
        "import-junit",
        str(db),
        str(report),
        "--project",
        "sample",
        "--runner-version",
        "pytest-9",
        "--profile",
        "unit",
        "--revision",
    ]
    report.write_text(
        '<testsuite><testcase name="one" classname="suite"><failure>'
        'PRIVATE_FAILURE_DATA</failure></testcase><testcase name="two"><skipped/>'
        '</testcase><testcase name="three"><error/></testcase></testsuite>'
    )
    assert main([*args, "a"]) == 0
    assert json.loads(capsys.readouterr().out)["run_id"] == 1
    report.write_text('<testsuite><testcase name="one" classname="suite"/></testsuite>')
    assert main([*args, "b"]) == 0
    assert b"PRIVATE_FAILURE_DATA" not in db.read_bytes()
    changes = {r["code"]: r["change"] for r in compare(db, 1, 2)}
    assert changes == {"one": "resolved", "two": "unknown", "three": "unknown"}
    assert main(["history", "list", str(db), "--project", "sample"]) == 0


@pytest.mark.parametrize(
    "document",
    [
        "<testsuite><testcase",
        "<other/>",
        "<testsuite/>",
        '<testsuite tests="2"><testcase name="only"/></testsuite>',
        '<testsuite tests="1" errors="1"><testcase name="only"/></testsuite>',
        '<testsuites><testcase name="outer"/></testsuites>',
        "<testsuite><testcase name='dup'/><testcase name='dup'/></testsuite>",
        "<!DOCTYPE testsuite><testsuite><testcase name='n'/></testsuite>",
    ],
)
def test_junit_bad_inputs_do_not_create_runs(tmp_path, document):
    db = tmp_path / "h.db"
    report = tmp_path / "report.xml"
    report.write_text(document)
    assert (
        main(
            [
                "history",
                "import-junit",
                str(db),
                str(report),
                "--project",
                "sample",
                "--runner-version",
                "pytest-9",
                "--profile",
                "unit",
                "--revision",
                "a",
            ]
        )
        == 2
    )
    assert not db.exists()


@pytest.mark.parametrize("identifier", ["0", "-1", "1208925819614629174706176"])
def test_invalid_run_ids_fail_without_traceback(tmp_path, capsys, identifier):
    assert main(["history", "diff", str(tmp_path / "missing.db"), identifier, "1"]) == 2
    error = capsys.readouterr().err
    assert "64-битными" in error
    assert "Traceback" not in error


@pytest.mark.parametrize("changed", ["# no image\n", "FROM ${IMAGE}\n", "FROM\n"])
def test_unknown_base_image_does_not_resolve_finding(tmp_path, changed):
    cfg = tmp_path / "Dockerfile"
    db = tmp_path / "h.db"
    cfg.write_text("FROM alpine:latest\n")
    assert scan(cfg, db, "first") == 1
    cfg.write_text(changed)
    scan(cfg, db, "second")
    changes = compare(db, 1, 2)
    assert changes and {item["change"] for item in changes} == {"unknown"}


@pytest.mark.parametrize("same_key", [True, False])
def test_parallel_initialization_is_atomic(tmp_path, same_key):
    count = 12
    for attempt in range(3):
        db = tmp_path / f"h-{attempt}.db"
        barrier = Barrier(count)

        def record(index, ready=barrier, database=db):
            ready.wait(10)
            return record_run(
                database,
                project="sample",
                revision="a",
                tool="junit",
                version="1",
                profile="unit",
                errors=0,
                records=[Record("check", ".", "pass")],
                run_key="single" if same_key else str(index),
            )

        with ThreadPoolExecutor(max_workers=count) as pool:
            writes = list(pool.map(record, range(count)))
        assert sum(inserted for _, inserted in writes) == (1 if same_key else count)
        assert len(list_runs(db, "sample")) == (1 if same_key else count)
