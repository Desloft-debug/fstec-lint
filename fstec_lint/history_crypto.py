"""Optional authenticated encryption for one local SQLite history snapshot."""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from .parsers.base import read_regular_bytes

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ENV = "FSTEC_LINT_HISTORY_KEY_FILE"
MAGIC = b"FSTH-ENC\x01"
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
ENCRYPTED_SUFFIX = ".fsth"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
OVERHEAD = len(MAGIC) + NONCE_BYTES + TAG_BYTES


class HistoryError(ValueError):
    pass


def key_path() -> Path | None:
    value = os.environ.get(KEY_ENV)
    if value == "":
        raise HistoryError(f"{KEY_ENV} задана без пути к файлу ключа")
    return Path(value) if value is not None else None


def load_key(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise HistoryError("ожидался обычный файл ключа истории, не ссылка")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        mode = os.fstat(source.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise HistoryError("ожидался обычный файл ключа истории")
        if os.name == "posix" and mode & 0o077:
            raise HistoryError("файл ключа не должен быть доступен группе или другим пользователям")
        key = source.read(KEY_BYTES + 1)
    if len(key) != KEY_BYTES:
        raise HistoryError("ожидался двоичный ключ истории из 32 байт")
    return key


def init_key(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise HistoryError("файл ключа уже существует") from None
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(os.urandom(KEY_BYTES))
            destination.flush()
            os.fsync(destination.fileno())
    except OSError:
        path.unlink(missing_ok=True)
        raise


def _cipher(key: bytes) -> AESGCM:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise HistoryError("установите fstec-lint[history-encryption]") from None
    return AESGCM(key)


class _SnapshotConnection(Protocol):
    def serialize(self) -> bytes: ...
    def deserialize(self, data: bytes) -> None: ...


def memory_database() -> sqlite3.Connection:
    if not all(hasattr(sqlite3.Connection, method) for method in ("serialize", "deserialize")):
        raise HistoryError("шифрование истории требует Python 3.11+ с SQLite serialize/deserialize")
    db = sqlite3.connect(":memory:")
    try:
        db.execute("PRAGMA temp_store = MEMORY")
        if db.execute("PRAGMA temp_store").fetchone()[0] != 2:
            raise HistoryError("не удалось отключить временные файлы SQLite")
        return db
    except BaseException:
        db.close()
        raise


def open_snapshot(db: sqlite3.Connection, path: Path, key: bytes) -> None:
    if path.is_symlink() or not path.is_file():
        raise HistoryError("ожидался обычный файл зашифрованной базы истории")
    raw = read_regular_bytes(path, MAX_DATABASE_BYTES + OVERHEAD + 1)
    if not raw.startswith(MAGIC):
        raise HistoryError("ожидалась зашифрованная история в формате FSTH")
    if not OVERHEAD < len(raw) <= MAX_DATABASE_BYTES + OVERHEAD:
        raise HistoryError("повреждённый файл истории или превышен лимит 64 МиБ")
    cipher = _cipher(key)
    from cryptography.exceptions import InvalidTag

    end_nonce = len(MAGIC) + NONCE_BYTES
    try:
        payload = cipher.decrypt(raw[len(MAGIC) : end_nonce], raw[end_nonce:], MAGIC)
    except InvalidTag:
        raise HistoryError("неверный ключ или нарушена целостность файла истории") from None
    cast(_SnapshotConnection, db).deserialize(payload)


@contextmanager
def writer_lock(path: Path) -> Iterator[None]:
    lock = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise HistoryError("файл истории занят другой записью; повторите операцию") from None
    os.close(fd)
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def check_snapshot_size(db: sqlite3.Connection) -> None:
    pages = db.execute("PRAGMA page_count").fetchone()[0]
    page_size = db.execute("PRAGMA page_size").fetchone()[0]
    if pages * page_size > MAX_DATABASE_BYTES:
        raise HistoryError("превышен лимит зашифрованной истории 64 МиБ")


def limit_growth(db: sqlite3.Connection) -> None:
    page_size = db.execute("PRAGMA page_size").fetchone()[0]
    db.execute(f"PRAGMA max_page_count = {MAX_DATABASE_BYTES // page_size}")


def save_snapshot(db: sqlite3.Connection, path: Path, key: bytes) -> None:
    check_snapshot_size(db)
    payload = cast(_SnapshotConnection, db).serialize()
    nonce = os.urandom(NONCE_BYTES)
    cipher = _cipher(key)
    ciphertext = cipher.encrypt(nonce, payload, MAGIC)
    fd, temp = tempfile.mkstemp(prefix=".fstec-history-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(MAGIC)
            destination.write(nonce)
            destination.write(ciphertext)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)
