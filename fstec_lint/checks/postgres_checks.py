"""Проверки для postgresql.conf и pg_hba.conf.

check_trust_or_md5_auth и check_open_hba_address работают с результатом
parse_pg_hba (список записей), остальные — с результатом
parse_postgresql_conf (dict параметров).
"""

from __future__ import annotations

OPEN_ADDRESSES = {"0.0.0.0/0", "::/0", "all", "samehost", "samenet"}


def check_trust_or_md5_auth(records: list[dict]) -> list[tuple[str, str]]:
    findings = []
    for rec in records:
        method = (rec.get("method") or "").lower()
        if method == "trust":
            findings.append((f"pg_hba: {rec['raw']}", "метод аутентификации 'trust' разрешает подключение без пароля"))
        elif method == "md5":
            findings.append((f"pg_hba: {rec['raw']}", "метод аутентификации 'md5' устарел, рекомендуется scram-sha-256"))
    return findings


def check_open_hba_address(records: list[dict]) -> list[tuple[str, str]]:
    findings = []
    for rec in records:
        addr = rec.get("address")
        if addr and addr.lower() in OPEN_ADDRESSES:
            findings.append((f"pg_hba: {rec['raw']}", f"подключение разрешено с адреса '{addr}' без ограничения по сети"))
    return findings


def check_listen_addresses(settings: dict) -> list[tuple[str, str]]:
    value = settings.get("listen_addresses", "")
    if value == "*":
        return [("postgresql.conf: listen_addresses", "listen_addresses = '*' — сервер слушает все сетевые интерфейсы")]
    return []


def check_logging_disabled(settings: dict) -> list[tuple[str, str]]:
    findings = []
    for key in ("log_connections", "log_disconnections"):
        value = settings.get(key, "off").lower()
        if value != "on":
            findings.append((f"postgresql.conf: {key}", f"{key} = {value} — события подключения/отключения не регистрируются"))
    return findings


def check_ssl_disabled(settings: dict) -> list[tuple[str, str]]:
    value = settings.get("ssl", "off").lower()
    if value != "on":
        return [("postgresql.conf: ssl", f"ssl = {value} — соединения с СУБД не шифруются")]
    return []


def check_password_encryption(settings: dict) -> list[tuple[str, str]]:
    value = settings.get("password_encryption", "md5").lower()
    if value != "scram-sha-256":
        return [("postgresql.conf: password_encryption", f"password_encryption = {value}, рекомендуется scram-sha-256")]
    return []


REGISTRY = {
    "P001": check_trust_or_md5_auth,
    "P002": check_open_hba_address,
    "P003": check_listen_addresses,
    "P004": check_logging_disabled,
    "P005": check_ssl_disabled,
    "P006": check_password_encryption,
}
