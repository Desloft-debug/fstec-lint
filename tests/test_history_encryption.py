"""The encrypted history path must authenticate before SQLite sees a snapshot."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from fstec_lint import history
from fstec_lint import history_crypto as crypto
from fstec_lint.cli import main

pytestmark = pytest.mark.skipif(
    not all(hasattr(crypto.sqlite3.Connection, name) for name in ("serialize", "deserialize")),
    reason="encrypted history needs Python >= 3.11 and SQLite serialization",
)


def _write(path: Path, *, revision: str = "revision-a") -> tuple[int, bool]:
    return history.record_run(
        path,
        project="internal-project-name",
        revision=revision,
        tool="junit",
        version="1",
        profile="unit",
        errors=0,
        records=[history.Record("secret-test-name", "secret-path", "pass")],
        run_key="job-1",
    )


@pytest.fixture
def encrypted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    pytest.importorskip("cryptography")
    key = tmp_path / "history.key"
    crypto.init_key(key)
    monkeypatch.setenv(crypto.KEY_ENV, str(key))
    return tmp_path / "history.fsth", key


def test_authenticated_history_roundtrip_without_plaintext(
    encrypted: tuple[Path, Path],
) -> None:
    path, key = encrypted
    assert _write(path) == (1, True)
    first = path.read_bytes()
    assert first.startswith(crypto.MAGIC)
    assert b"SQLite format 3" not in first
    assert b"internal-project-name" not in first
    assert b"secret-test-name" not in first
    assert b"secret-path" not in first
    assert not list(path.parent.glob("*.tmp"))
    assert not path.with_name(path.name + ".lock").exists()
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name, key.name]
    assert _write(path) == (1, False)
    assert path.read_bytes() == first
    assert _write(path, revision="revision-b") == (2, True)
    assert path.read_bytes()[: crypto.OVERHEAD] != first[: crypto.OVERHEAD]
    rows = history.list_runs(path, "internal-project-name")
    assert [row["revision"] for row in rows] == ["revision-a", "revision-b"]
    assert history.compare(path, 1, 2) == []


def test_missing_key_never_creates_or_opens_plain_database(
    encrypted: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = encrypted
    monkeypatch.delenv(crypto.KEY_ENV)
    with pytest.raises(history.HistoryError, match=crypto.KEY_ENV):
        _write(path)
    assert not path.exists()
    monkeypatch.setenv(crypto.KEY_ENV, "")
    with pytest.raises(history.HistoryError, match=crypto.KEY_ENV):
        _write(path)
    assert not path.exists()


def test_wrong_key_does_not_modify_ciphertext(
    encrypted: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, key = encrypted
    _write(path)
    content = path.read_bytes()
    other_key = key.with_name("other.key")
    crypto.init_key(other_key)
    monkeypatch.setenv(crypto.KEY_ENV, str(other_key))
    with pytest.raises(history.HistoryError, match="ключ или нарушена целостность"):
        _write(path, revision="revision-b")
    with pytest.raises(history.HistoryError, match="ключ или нарушена целостность"):
        history.list_runs(path, "internal-project-name")
    assert path.read_bytes() == content


@pytest.mark.parametrize(
    "index", [0, len(crypto.MAGIC), len(crypto.MAGIC) + crypto.NONCE_BYTES, -1]
)
def test_modified_snapshot_rejected(encrypted: tuple[Path, Path], index: int) -> None:
    path, _ = encrypted
    _write(path)
    content = bytearray(path.read_bytes())
    content[index] ^= 0x01
    path.write_bytes(content)
    with pytest.raises(history.HistoryError, match="формате FSTH|нарушена целостность"):
        _write(path, revision="revision-b")
    assert path.read_bytes() == content


def test_migrates_plain_database_without_overwriting(
    encrypted: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    destination, key = encrypted
    source = destination.with_suffix(".sqlite3")
    monkeypatch.delenv(crypto.KEY_ENV)
    _write(source)
    plain = source.read_bytes()
    expect = history.list_runs(source, "internal-project-name")
    monkeypatch.setenv(crypto.KEY_ENV, str(key))
    with pytest.raises(history.HistoryError, match="расширение .fsth"):
        _write(source, revision="revision-b")
    history.encrypt_history(source, destination)
    assert source.read_bytes() == plain
    assert history.list_runs(destination, "internal-project-name") == expect
    encrypted_content = destination.read_bytes()
    with pytest.raises(history.HistoryError, match="уже занят"):
        history.encrypt_history(source, destination)
    assert destination.read_bytes() == encrypted_content
    destination.write_bytes(plain)
    with pytest.raises(history.HistoryError, match="формате FSTH"):
        history.list_runs(destination, "internal-project-name")


def test_migration_supports_committed_rows_in_wal(
    encrypted: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    destination, key = encrypted
    source = destination.with_suffix(".sqlite3")
    monkeypatch.delenv(crypto.KEY_ENV)
    _write(source)
    connection = sqlite3.connect(source)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.execute("BEGIN")
        assert connection.execute("SELECT count(*) FROM runs").fetchone() == (1,)
        _write(source, revision="revision-b")
        assert Path(str(source) + "-wal").exists()
        monkeypatch.setenv(crypto.KEY_ENV, str(key))
        history.encrypt_history(source, destination)
        assert len(history.list_runs(destination, "internal-project-name")) == 2
        assert _write(destination, revision="revision-c") == (3, True)
        connection.commit()
        assert connection.execute("SELECT count(*) FROM runs").fetchone() == (2,)
    finally:
        connection.close()


def test_oversize_migration_preserves_source(
    encrypted: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    destination, key = encrypted
    source = destination.with_suffix(".sqlite3")
    monkeypatch.delenv(crypto.KEY_ENV)
    _write(source)
    before = source.read_bytes()
    monkeypatch.setenv(crypto.KEY_ENV, str(key))
    monkeypatch.setattr(crypto, "MAX_DATABASE_BYTES", 128)
    with pytest.raises(history.HistoryError, match="превышен лимит"):
        history.encrypt_history(source, destination)
    assert source.read_bytes() == before
    assert not destination.exists()


def test_replacement_failure_leaves_original_and_removes_staging(
    encrypted: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = encrypted
    _write(path)
    before = path.read_bytes()

    def fail_replace(temp: str, destination: Path) -> None:
        assert Path(temp).read_bytes().startswith(crypto.MAGIC)
        assert destination == path
        raise PermissionError("test")

    monkeypatch.setattr(crypto.os, "replace", fail_replace)
    with pytest.raises(PermissionError):
        _write(path, revision="revision-b")
    assert path.read_bytes() == before
    assert not list(path.parent.glob("*.tmp"))
    assert not path.with_name(path.name + ".lock").exists()


def test_parallel_writer_does_not_read_or_write_uncommitted_state(
    encrypted: tuple[Path, Path],
) -> None:
    path, _ = encrypted
    _write(path)
    before = path.read_bytes()
    with crypto.writer_lock(path):
        assert history.list_runs(path, "internal-project-name")[0]["revision"] == "revision-a"
        with pytest.raises(history.HistoryError, match="занят другой записью"):
            _write(path, revision="revision-b")
        assert path.read_bytes() == before
    assert _write(path, revision="revision-b") == (2, True)


def test_alias_to_key_is_rejected(encrypted: tuple[Path, Path]) -> None:
    path, key = encrypted
    with pytest.raises(history.HistoryError, match="файл ключа должен быть отделён"):
        history.validate_db_path(path, [key])
    assert not path.exists()
    assert len(key.read_bytes()) == crypto.KEY_BYTES


@pytest.mark.skipif(os.name != "posix", reason="Windows uses filesystem ACLs")
def test_posix_key_permissions_and_no_overwrite(encrypted: tuple[Path, Path]) -> None:
    path, key = encrypted
    assert key.stat().st_mode & 0o777 == 0o600
    original = key.read_bytes()
    with pytest.raises(history.HistoryError, match="уже существует"):
        crypto.init_key(key)
    assert key.read_bytes() == original
    key.chmod(0o640)
    with pytest.raises(history.HistoryError, match="доступен группе"):
        _write(path)
    assert not path.exists()


def test_cli_scan_list_import_diff(
    encrypted: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _ = encrypted
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine:latest\n", encoding="utf-8")
    scan = [
        str(dockerfile),
        "--select",
        "D004",
        "--history-db",
        str(path),
        "--project",
        "demo",
        "--fail-on",
        "none",
    ]
    assert main([*scan, "--revision", "rev-a"]) == 0
    dockerfile.write_text("FROM alpine:3.22\n", encoding="utf-8")
    assert main([*scan, "--revision", "rev-b"]) == 0
    capsys.readouterr()
    assert main(["history", "diff", str(path), "1", "2"]) == 0
    assert '"change": "resolved"' in capsys.readouterr().out
    junit = tmp_path / "unit.xml"
    junit.write_text('<testsuite tests="1"><testcase name="case"/></testsuite>', encoding="utf-8")
    assert (
        main(
            [
                "history",
                "import-junit",
                str(path),
                str(junit),
                "--project",
                "demo",
                "--revision",
                "rev-b",
                "--runner-version",
                "1",
                "--profile",
                "unit",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["history", "list", str(path), "--project", "demo"]) == 0
    assert '"tool": "junit"' in capsys.readouterr().out
