"""Локальная история проверок. Не хранит исходный текст или диагностику."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import __version__, history_crypto
from .engine import ScanResult
from .history_crypto import HistoryError as HistoryError
from .parsers.base import read_regular_bytes

APP_ID = 0x46535448  # FSTH
SCHEMA_VERSION = 1
MAX_JUNIT_BYTES = 4 * 1024 * 1024
MAX_CHECKS = 100_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS revisions (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    revision TEXT NOT NULL,
    UNIQUE (project_id, revision)
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    revision_id INTEGER NOT NULL REFERENCES revisions(id),
    tool TEXT NOT NULL,
    version TEXT NOT NULL,
    profile TEXT NOT NULL,
    run_key TEXT,
    payload_sha256 TEXT NOT NULL,
    errors INTEGER NOT NULL CHECK (errors >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (revision_id, tool, run_key),
    UNIQUE (id, tool)
);
CREATE TABLE IF NOT EXISTS definitions (
    tool TEXT NOT NULL,
    code TEXT NOT NULL,
    PRIMARY KEY (tool, code)
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    tool TEXT NOT NULL,
    code TEXT NOT NULL,
    scope TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'skip', 'unavailable')),
    FOREIGN KEY (run_id, tool) REFERENCES runs(id, tool),
    FOREIGN KEY (tool, code) REFERENCES definitions(tool, code),
    UNIQUE (run_id, code, scope)
);
CREATE TABLE IF NOT EXISTS findings (
    observation_id INTEGER NOT NULL REFERENCES observations(id),
    fingerprint TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER CHECK (line IS NULL OR line > 0),
    PRIMARY KEY (observation_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS observations_definition ON observations (tool, code);
"""


@dataclass(frozen=True)
class Record:
    code: str
    scope: str
    status: str
    findings: tuple[tuple[str, str, int | None], ...] = ()


def _label(value: str, limit: int = 180) -> str:
    if not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise HistoryError("пустой, слишком длинный или недопустимый идентификатор")
    return value


def _relative(path: Path, root: Path) -> str:
    try:
        if not path.resolve().is_relative_to(root):
            raise ValueError("out of scope")
        try:
            # Keep distinct in-root paths distinct when a file has a symlink alias.
            relative = path.absolute().relative_to(root)
        except ValueError:
            relative = path.resolve().relative_to(root)
        return _label(relative.as_posix(), 1024)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HistoryError("путь наблюдения вне границы или не подходит для истории") from exc


@lru_cache(maxsize=1)
def scanner_fingerprint() -> str:
    """Distinguish different private builds sharing the same version."""
    root = Path(__file__).resolve().parent
    manifest = {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file() and p.suffix in {".py", ".yaml"}
    }
    return profile_digest(manifest)


def profile_digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()


def scan_records(result: ScanResult, scope_root: Path) -> list[Record]:
    if result.checks is None:
        raise HistoryError("покрытие правил не записано")
    if len(result.checks) > MAX_CHECKS:
        raise HistoryError("превышен лимит наблюдений истории")
    records = []
    for observation in result.checks:
        entries: dict[str, tuple[str, str, int | None]] = {}
        for finding in observation.findings:
            path = _relative(Path(finding.file), scope_root)
            fingerprint = hashlib.sha256(
                finding.fingerprint(relative_file=path).encode()
            ).hexdigest()
            entries.setdefault(fingerprint, (fingerprint, path, finding.line))
        records.append(
            Record(
                observation.rule_id,
                _relative(observation.file, scope_root),
                observation.status,
                tuple(sorted(entries.values())),
            )
        )
    return records


def validate_db_path(path: Path, other_paths: Sequence[Path]) -> None:
    try:
        key = history_crypto.key_path()
        if key is not None:
            for candidate in (path, *other_paths):
                if candidate.resolve() == key.resolve() or (
                    candidate.exists() and key.exists() and candidate.samefile(key)
                ):
                    raise HistoryError("файл ключа должен быть отделён от базы, входов и отчётов")
        for other in other_paths:
            if path.resolve() == other.resolve() or (
                path.exists() and other.exists() and path.samefile(other)
            ):
                raise HistoryError("база истории должна быть отдельным файлом")
    except (OSError, RuntimeError) as exc:
        raise HistoryError("не удалось проверить путь базы истории") from exc
    suffix = path.suffix.lower()
    if suffix == history_crypto.ENCRYPTED_SUFFIX and not path.name.lower().startswith(".env"):
        if key is None:
            raise HistoryError(f"для зашифрованной истории задайте {history_crypto.KEY_ENV}")
        return
    if key is not None:
        raise HistoryError("для зашифрованной истории используйте расширение .fsth")
    if suffix not in {".sqlite", ".sqlite3", ".db"} or path.name.startswith(".env"):
        raise HistoryError("обычная база истории должна оканчиваться на .sqlite, .sqlite3 или .db")


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[str, ...], ...]:
    rows = connection.execute(
        "SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master "
        "WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name"
    )
    return tuple(tuple(row) for row in rows)


@lru_cache(maxsize=1)
def _expected_schema_signature() -> tuple[tuple[str, ...], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA)
        return _schema_signature(connection)
    finally:
        connection.close()


def _prepare_connection(connection: sqlite3.Connection, *, write: bool, initialize: bool) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise HistoryError("не удалось включить внешние ключи")
    connection.execute("PRAGMA trusted_schema = OFF")
    trusted = connection.execute("PRAGMA trusted_schema").fetchone()
    if trusted is None or trusted[0] != 0:
        raise HistoryError("для истории требуется SQLite 3.31+ с trusted_schema")
    connection.execute("PRAGMA cell_size_check = ON")
    # Read both header fields in one snapshot. During the very first
    # parallel import separate autocommit reads can straddle schema setup.
    connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
    application = connection.execute("PRAGMA application_id").fetchone()[0]
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if application == 0 and version == 0 and initialize:
        if connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
            raise HistoryError("файл содержит другую базу")
        for statement in SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)
        connection.execute(f"PRAGMA application_id = {APP_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        application, version = APP_ID, SCHEMA_VERSION
    if (application, version) != (APP_ID, SCHEMA_VERSION):
        raise HistoryError("неподдерживаемая база истории")
    if _schema_signature(connection) != _expected_schema_signature():
        raise HistoryError("структура базы истории не совпадает со схемой fstec-lint")
    if write:
        connection.commit()


def _check_history_file(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise HistoryError("ожидался обычный файл базы данных")


@contextmanager
def _connect_plain(path: Path, *, create: bool = False) -> Iterator[sqlite3.Connection]:
    _check_history_file(path)
    if create and not path.exists():
        try:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"):
                pass
        except FileExistsError:
            pass
    length = len(history_crypto.MAGIC)
    if path.exists() and read_regular_bytes(path, length) == history_crypto.MAGIC:
        raise HistoryError("ожидалась обычная, а не зашифрованная база SQLite")
    mode = "rw" if create else "ro"
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode={mode}", uri=True, timeout=5)
    try:
        _prepare_connection(connection, write=create, initialize=create)
        yield connection
    finally:
        connection.close()


@contextmanager
def _connect(path: Path, *, create: bool = False) -> Iterator[sqlite3.Connection]:
    validate_db_path(path, [])
    key_file = history_crypto.key_path()
    if key_file is None:
        with _connect_plain(path, create=create) as db:
            yield db
        return
    key = history_crypto.load_key(key_file)
    with history_crypto.writer_lock(path) if create else nullcontext():
        _check_history_file(path)
        exists = path.exists()
        db = history_crypto.memory_database()
        try:
            if exists or not create:
                history_crypto.open_snapshot(db, path, key)
            _prepare_connection(db, write=create, initialize=create and not exists)
            if create:
                history_crypto.limit_growth(db)
            before_changes = db.total_changes
            yield db
            if create and (not exists or db.total_changes != before_changes):
                if db.in_transaction:
                    raise HistoryError("изменения SQLite не зафиксированы")
                history_crypto.save_snapshot(db, path, key)
        finally:
            db.close()


def encrypt_history(source: Path, destination: Path) -> None:
    key_file = history_crypto.key_path()
    if key_file is None:
        raise HistoryError(f"укажите файл ключа через {history_crypto.KEY_ENV}")
    validate_db_path(destination, [source])
    key = history_crypto.load_key(key_file)
    with history_crypto.writer_lock(destination):
        # Refuse even a dangling symlink or an empty existing destination.
        if destination.exists() or destination.is_symlink():
            raise HistoryError("путь для зашифрованной копии уже занят")
        with _connect_plain(source) as original:
            history_crypto.check_snapshot_size(original)
            db = history_crypto.memory_database()
            try:
                original.backup(db)
                if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise HistoryError("исходная база SQLite повреждена")
                if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise HistoryError("в исходной истории нарушены внешние ключи")
                # A backup can inherit WAL format bytes from disk, even though the
                # connection reports journal_mode=memory. Rebuild the memory copy
                # so deserialization does not try to open external WAL files.
                db.execute("VACUUM")
                history_crypto.save_snapshot(db, destination, key)
            finally:
                db.close()


def record_run(
    path: Path,
    *,
    project: str,
    revision: str,
    tool: str,
    version: str,
    profile: str,
    errors: int,
    records: Sequence[Record],
    run_key: str | None = None,
) -> tuple[int, bool]:
    for label in (project, revision, tool, version, profile):
        _label(label)
    if run_key is not None:
        _label(run_key)
    if len(records) > MAX_CHECKS:
        raise HistoryError("превышен лимит наблюдений истории")
    ordered = sorted(records, key=lambda r: (r.code, r.scope))
    signature = profile_digest(
        [
            version,
            profile,
            errors,
            [(r.code, r.scope, r.status, r.findings) for r in ordered],
        ]
    )
    with _connect(path, create=True) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR IGNORE INTO projects(slug) VALUES (?)", (project,))
        project_id = db.execute("SELECT id FROM projects WHERE slug=?", (project,)).fetchone()[0]
        db.execute(
            "INSERT OR IGNORE INTO revisions(project_id,revision) VALUES (?,?)",
            (project_id, revision),
        )
        revision_id = db.execute(
            "SELECT id FROM revisions WHERE project_id=? AND revision=?", (project_id, revision)
        ).fetchone()[0]
        if run_key is not None:
            prior = db.execute(
                "SELECT id,payload_sha256 FROM runs WHERE revision_id=? AND tool=? AND run_key=?",
                (revision_id, tool, run_key),
            ).fetchone()
            if prior:
                if prior["payload_sha256"] != signature:
                    raise HistoryError("ключ прогона уже использован для другого результата")
                return int(prior["id"]), False
        run = db.execute(
            """INSERT INTO runs(revision_id,tool,version,profile,run_key,payload_sha256,errors)
               VALUES (?,?,?,?,?,?,?)""",
            (revision_id, tool, version, profile, run_key, signature, errors),
        )
        run_id = int(run.lastrowid or 0)
        db.executemany(
            "INSERT OR IGNORE INTO definitions(tool,code) VALUES (?,?)",
            ((tool, code) for code in sorted({r.code for r in ordered})),
        )
        for item in ordered:
            cursor = db.execute(
                "INSERT INTO observations(run_id,tool,code,scope,status) VALUES (?,?,?,?,?)",
                (run_id, tool, item.code, item.scope, item.status),
            )
            db.executemany(
                "INSERT INTO findings(observation_id,fingerprint,path,line) VALUES (?,?,?,?)",
                ((cursor.lastrowid, *values) for values in item.findings),
            )
        return run_id, True


def record_scan(
    db: Path,
    root: Path,
    result: ScanResult,
    *,
    project: str,
    revision: str,
    profile: str,
    run_key: str | None,
) -> tuple[int, bool]:
    scope_root = root.resolve().parent if root.is_file() else root.resolve()
    return record_run(
        db,
        project=project,
        revision=revision,
        tool="fstec-lint",
        version=__version__,
        profile=profile,
        errors=len(result.errors),
        records=scan_records(result, scope_root),
        run_key=run_key,
    )


def list_runs(path: Path, project: str) -> list[dict]:
    with _connect(path) as db:
        return [
            dict(row)
            for row in db.execute(
                """SELECT runs.id, revision, tool, version, errors, created_at,
               (SELECT count(*) FROM observations WHERE run_id=runs.id) AS checks
               FROM runs JOIN revisions ON revisions.id=runs.revision_id
               JOIN projects ON projects.id=revisions.project_id
               WHERE projects.slug=? ORDER BY runs.id""",
                (project,),
            )
        ]


def _diff(db: sqlite3.Connection, old: int, new: int) -> list[dict]:
    meta = db.execute(
        """SELECT runs.*, project_id FROM runs JOIN revisions ON revisions.id=revision_id
           WHERE runs.id IN (?,?)""",
        (old, new),
    ).fetchall()
    if len(meta) != 2:
        raise HistoryError("нужны два разных существующих прогона")
    a, b = sorted(meta, key=lambda row: row["id"] != old)
    fields = ("project_id", "tool", "version", "profile")
    if any(a[key] != b[key] for key in fields):
        raise HistoryError("сравниваются только прогоны одного проекта, инструмента и профиля")
    rows = db.execute(
        """WITH
        prev AS (SELECT * FROM observations WHERE run_id=:old),
        next AS (SELECT * FROM observations WHERE run_id=:new),
        scopes AS (SELECT code,scope FROM prev UNION SELECT code,scope FROM next),
        old_findings AS (
            SELECT code,scope,fingerprint,path,line
            FROM prev JOIN findings ON observation_id=prev.id
        ),
        new_findings AS (
            SELECT code,scope,fingerprint,path,line
            FROM next JOIN findings ON observation_id=next.id
        ),
        changes AS (
            SELECT p.code,p.scope,p.fingerprint,p.path,p.line,'old' AS side
            FROM old_findings p
            WHERE NOT EXISTS (SELECT 1 FROM new_findings n WHERE
                (n.code,n.scope,n.fingerprint)=(p.code,p.scope,p.fingerprint))
            UNION ALL
            SELECT n.code,n.scope,n.fingerprint,n.path,n.line,'new'
            FROM new_findings n
            WHERE NOT EXISTS (SELECT 1 FROM old_findings p WHERE
                (p.code,p.scope,p.fingerprint)=(n.code,n.scope,n.fingerprint))
            UNION ALL
            SELECT scopes.code,scopes.scope,NULL,NULL,NULL,'check'
            FROM scopes
            LEFT JOIN prev USING (code,scope)
            LEFT JOIN next USING (code,scope)
            WHERE COALESCE(prev.status,'missing') <> COALESCE(next.status,'missing')
            AND (:is_junit OR NOT EXISTS (
                SELECT 1 FROM old_findings WHERE (code,scope)=(scopes.code,scopes.scope)
                UNION ALL
                SELECT 1 FROM new_findings WHERE (code,scope)=(scopes.code,scopes.scope)
            ))
        )
        SELECT changes.code,changes.scope,fingerprint,path,line,
               prev.status AS before,next.status AS after,
               CASE
               WHEN :incomplete OR COALESCE(prev.status,'missing') NOT IN ('pass','fail')
                    OR COALESCE(next.status,'missing') NOT IN ('pass','fail') THEN 'unknown'
               WHEN side='old' OR (side='check' AND next.status='pass') THEN 'resolved'
               WHEN side='new' OR (side='check' AND next.status='fail') THEN 'new'
               ELSE 'unknown' END AS change
        FROM changes
        LEFT JOIN prev ON (prev.code,prev.scope)=(changes.code,changes.scope)
        LEFT JOIN next ON (next.code,next.scope)=(changes.code,changes.scope)
        ORDER BY changes.scope,changes.code,changes.fingerprint,side""",
        dict(
            old=old,
            new=new,
            incomplete=bool(a["errors"] or b["errors"]),
            is_junit=a["tool"] == "junit",
        ),
    )
    return [dict(row) for row in rows]


def compare(path: Path, old: int, new: int) -> list[dict]:
    if not (0 < old < 2**63 and 0 < new < 2**63):
        raise HistoryError("идентификаторы прогонов должны быть положительными 64-битными числами")
    with _connect(path) as db:
        return _diff(db, old, new)


_JUNIT_STATES = {"pass": 0, "fail": 1, "skip": 2, "unavailable": 3}
_JUNIT_TOTALS = ("tests", "failures", "skipped", "errors")


def _check_junit_totals(root: ET.Element, states: dict[ET.Element, str]) -> None:
    totals: dict[ET.Element, list[int]] = {}
    for element in reversed(list(root.iter())):
        if element in states:
            counts = [0, 0, 0, 0]
            counts[_JUNIT_STATES[states[element]]] = 1
        else:
            counts = [0, 0, 0, 0]
            for child in element:
                child_count = totals[child]
                if child.tag == "testcase" and element.tag != "testsuite":
                    raise HistoryError("testcase должен находиться непосредственно в testsuite")
                for index, amount in enumerate(child_count):
                    counts[index] += amount
        totals[element] = counts
        if element.tag in {"testsuites", "testsuite"}:
            declared = (sum(counts), *counts[1:])
            for name, amount in zip(_JUNIT_TOTALS, declared, strict=True):
                value = element.get(name)
                if value is not None and (
                    not re.fullmatch(r"[0-9]{1,9}", value) or int(value) != amount
                ):
                    raise HistoryError("сводка JUnit не совпадает со статусами отдельных тестов")


def read_junit(path: Path) -> list[Record]:
    try:
        raw = read_regular_bytes(path, MAX_JUNIT_BYTES + 1)
    except ValueError as exc:
        raise HistoryError("отчёт JUnit должен быть обычным файлом") from exc
    if len(raw) > MAX_JUNIT_BYTES or b"\x00" in raw:
        raise HistoryError("ожидался отчёт JUnit XML в UTF-8 в пределах лимита")
    content = raw.decode("utf-8-sig")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, re.IGNORECASE):
        raise HistoryError("в отчёте JUnit не разрешены DTD и объявления сущностей")
    root = ET.fromstring(content)
    if root.tag not in {"testsuites", "testsuite"}:
        raise HistoryError("ожидался корневой элемент testsuite(s)")
    rows: list[Record] = []
    keys: set[tuple[str, str]] = set()
    case_states: dict[ET.Element, str] = {}
    for case in root.iter("testcase"):
        name = _label(case.attrib.get("name", ""))
        scope = _label(case.attrib.get("classname") or ".", 1024)
        states = {child.tag for child in case}
        known = {"skipped", "failure", "error", "properties", "system-out", "system-err"}
        if states - known or len(states & {"skipped", "failure", "error"}) > 1:
            raise HistoryError("неоднозначный или неподдерживаемый статус теста JUnit")
        status = (
            "unavailable"
            if "error" in states
            else "fail"
            if "failure" in states
            else "skip"
            if "skipped" in states
            else "pass"
        )
        key = (scope, name)
        if key in keys or len(rows) >= MAX_CHECKS:
            raise HistoryError("повторяющееся имя теста или превышен лимит наблюдений")
        keys.add(key)
        rows.append(Record(name, scope, status))
        case_states[case] = status
    if not rows:
        raise HistoryError("отчёт JUnit не содержит результатов тестов")
    _check_junit_totals(root, case_states)
    return rows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fstec-lint history")
    operations = parser.add_subparsers(dest="operation", required=True)
    listing = operations.add_parser("list", help="показать прогоны проекта")
    listing.add_argument("db", type=Path)
    listing.add_argument("--project", required=True)
    difference = operations.add_parser("diff", help="сравнить два прогона")
    difference.add_argument("db", type=Path)
    difference.add_argument("old", type=int)
    difference.add_argument("new", type=int)
    importing = operations.add_parser("import-junit", help="импортировать статусы тестов")
    importing.add_argument("db", type=Path)
    importing.add_argument("report", type=Path)
    importing.add_argument("--project", required=True)
    importing.add_argument("--revision", required=True)
    importing.add_argument("--runner-version", required=True)
    importing.add_argument("--profile", required=True)
    importing.add_argument("--run-key")
    key = operations.add_parser("init-key", help="создать новый случайный ключ истории")
    key.add_argument("key", type=Path)
    encrypt = operations.add_parser("encrypt", help="сделать зашифрованную копию базы SQLite")
    encrypt.add_argument("source", type=Path)
    encrypt.add_argument("destination", type=Path)
    return parser


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        result: object
        if args.operation == "list":
            result = list_runs(args.db, args.project)
        elif args.operation == "diff":
            result = compare(args.db, args.old, args.new)
        elif args.operation == "init-key":
            history_crypto.init_key(args.key)
            result = {"created": True}
        elif args.operation == "encrypt":
            encrypt_history(args.source, args.destination)
            result = {"encrypted": True}
        else:
            validate_db_path(args.db, [args.report])
            run_id, inserted = record_run(
                args.db,
                project=args.project,
                revision=args.revision,
                tool="junit",
                version=args.runner_version,
                profile=args.profile,
                errors=0,
                records=read_junit(args.report),
                run_key=args.run_key,
            )
            result = {"run_id": run_id, "inserted": inserted}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except HistoryError as exc:
        print(f"fstec-lint history: {exc}", file=sys.stderr)
    except (OSError, RuntimeError, sqlite3.Error, ET.ParseError, UnicodeError) as exc:
        print(f"fstec-lint history: операция не завершена ({type(exc).__name__})", file=sys.stderr)
    return 2
