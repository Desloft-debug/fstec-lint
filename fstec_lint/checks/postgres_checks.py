"""Проверки postgresql.conf и pg_hba.conf.

Первые две функции работают со списком записей из parse_pg_hba,
остальные — со словарём параметров из parse_postgresql_conf.
"""

from __future__ import annotations

from .base import CheckResults, config_line

OPEN_ADDRESSES = {
    "0.0.0.0/0",
    "::/0",
    "all",
    "samehost",
    "samenet",
    # Та же «любая сеть», записанная устаревшей формой «адрес маска».
    "0.0.0.0 0.0.0.0",
    ":: ::",
}


def check_trust_or_md5_auth(records: list[dict]) -> CheckResults:
    findings = []
    for rec in records:
        method = (rec.get("method") or "").lower()
        if method == "trust":
            findings.append(
                (
                    f"pg_hba: {rec['raw']}",
                    "метод аутентификации 'trust' разрешает подключение без пароля",
                    rec.get("line"),
                )
            )
        elif method == "md5":
            findings.append(
                (
                    f"pg_hba: {rec['raw']}",
                    "метод аутентификации 'md5' устарел, рекомендуется scram-sha-256",
                    rec.get("line"),
                )
            )
    return findings


def check_open_hba_address(records: list[dict]) -> CheckResults:
    findings = []
    for rec in records:
        addr = rec.get("address")
        if addr and addr.lower() in OPEN_ADDRESSES:
            findings.append(
                (
                    f"pg_hba: {rec['raw']}",
                    f"подключение разрешено с адреса '{addr}' без ограничения по сети",
                    rec.get("line"),
                )
            )
    return findings


def check_listen_addresses(settings: dict) -> CheckResults:
    value = settings.get("listen_addresses", "")
    if value == "*":
        return [
            (
                "postgresql.conf: listen_addresses",
                "listen_addresses = '*' — сервер слушает все сетевые интерфейсы",
                config_line(settings, "listen_addresses"),
            )
        ]
    return []


def check_logging_disabled(settings: dict) -> CheckResults:
    findings = []
    for key in ("log_connections", "log_disconnections"):
        value = settings.get(key, "off").lower()
        if value != "on":
            findings.append(
                (
                    f"postgresql.conf: {key}",
                    f"{key} = {value} — события подключения/отключения не регистрируются",
                    config_line(settings, key),
                )
            )
    return findings


def check_ssl_disabled(settings: dict) -> CheckResults:
    value = settings.get("ssl", "off").lower()
    if value != "on":
        return [
            (
                "postgresql.conf: ssl",
                f"ssl = {value} — соединения с СУБД не шифруются",
                config_line(settings, "ssl"),
            )
        ]
    return []


def check_password_encryption(settings: dict) -> CheckResults:
    value = settings.get("password_encryption", "md5").lower()
    if value != "scram-sha-256":
        return [
            (
                "postgresql.conf: password_encryption",
                f"password_encryption = {value}, рекомендуется scram-sha-256",
                config_line(settings, "password_encryption"),
            )
        ]
    return []


def check_statement_logging_disabled(settings: dict) -> CheckResults:
    value = settings.get("log_statement", "none").lower()
    if value not in ("ddl", "mod", "all"):
        return [
            (
                "postgresql.conf: log_statement",
                f"log_statement = {value} — изменения схемы и данных "
                "не фиксируются в журнале аудита",
                config_line(settings, "log_statement"),
            )
        ]
    return []


def check_missing_statement_timeout(settings: dict) -> CheckResults:
    value = settings.get("statement_timeout", "0").strip()
    if value in ("0", "0ms", "0s", "0min", "0h", "0d", ""):
        return [
            (
                "postgresql.conf: statement_timeout",
                "statement_timeout не задан (0) — зависшие или намеренно долгие "
                "запросы не будут принудительно прерваны",
                config_line(settings, "statement_timeout"),
            )
        ]
    return []


# Два реестра, а не один: pg_hba и postgresql.conf парсятся в разную
# форму (список записей vs словарь), так надёжнее.
PG_HBA_REGISTRY = {
    "P001": check_trust_or_md5_auth,
    "P002": check_open_hba_address,
}

POSTGRESQL_CONF_REGISTRY = {
    "P003": check_listen_addresses,
    "P004": check_logging_disabled,
    "P005": check_ssl_disabled,
    "P006": check_password_encryption,
    "P007": check_statement_logging_disabled,
    "P008": check_missing_statement_timeout,
}
