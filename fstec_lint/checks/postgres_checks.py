"""Проверки postgresql.conf и pg_hba.conf.

Первые две функции работают со списком записей из parse_pg_hba,
остальные — со словарём параметров из parse_postgresql_conf.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterator

from ..parsers.base import SourceLine
from .base import CheckResults, config_line

PG_TRUE_VALUES = {"on", "true", "yes", "1"}
PG_CONNECTION_EVENTS = {"receipt", "authentication", "authorization", "setup_durations", "all"}

# PostgreSQL allows whitespace before a case-sensitive time unit in a quoted
# setting. This recognizes explicit numeric zero, not other values that an
# installed server might round to zero or reject.
_ZERO_TIMEOUT = re.compile(r"[+-]?(?:0+(?:\.0*)?|\.0+)(?:[ \t]*(?:us|ms|s|min|h|d))?")

OPEN_ADDRESSES = {
    "0.0.0.0/0",
    "::/0",
    "all",
    # Та же «любая сеть», записанная устаревшей формой «адрес маска».
    "0.0.0.0 0.0.0.0",
    ":: ::",
}


def _hba_locations(records: list[dict]) -> Iterator[tuple[dict, str]]:
    """Identify records without including options, raw input, or line numbers.

    Occurrences distinguish records with identical structural fields. Their order
    matters when identical records are inserted, deleted, or rearranged.
    """
    occurrences: dict[tuple[str, str], int] = defaultdict(int)
    seen: set[tuple[str, int]] = set()
    for rec in records:
        line = rec.get("line")
        source = line.file if isinstance(line, SourceLine) else ""
        if isinstance(line, SourceLine):
            position = (source, int(line))
            if position in seen:
                continue
            seen.add(position)
        fields = [rec.get(key) for key in ("type", "database", "user", "address", "method")]
        encoded = json.dumps(fields, ensure_ascii=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        key = (source, digest)
        occurrences[key] += 1
        yield rec, f"pg_hba:v2:{digest}:{occurrences[key]}"


def check_trust_auth(records: list[dict]) -> CheckResults:
    return [
        (location, "запись использует trust, без проверки подлинности", rec.get("line"))
        for rec, location in _hba_locations(records)
        if (rec.get("method") or "").lower() == "trust"
    ]


def check_md5_auth(records: list[dict]) -> CheckResults:
    return [
        (
            location,
            "задан устаревающий метод md5; фактический протокол зависит "
            "от сохранённого проверочного значения",
            rec.get("line"),
        )
        for rec, location in _hba_locations(records)
        if (rec.get("method") or "").lower() == "md5"
    ]


def check_open_hba_address(records: list[dict]) -> CheckResults:
    findings = []
    for rec, location in _hba_locations(records):
        addr = rec.get("address")
        method = (rec.get("method") or "").lower()
        if addr and addr.lower() in OPEN_ADDRESSES and method != "reject":
            findings.append(
                (
                    location,
                    f"запись с адресом {addr} подходит для всего семейства; порядок правил, "
                    "аутентификация и внешний доступ не проверены",
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
        value = settings.get(key, "off").strip().lower()
        events = {event.strip() for event in value.split(",")}
        connection_logging = (
            key == "log_connections"
            and events <= PG_CONNECTION_EVENTS
            and bool(events - {"setup_durations"})
        )
        if value not in PG_TRUE_VALUES and not connection_logging:
            findings.append(
                (
                    f"postgresql.conf: {key}",
                    f"{key}: не подтверждено журналирование соответствующих событий",
                    config_line(settings, key),
                )
            )
    return findings


def check_ssl_disabled(settings: dict) -> CheckResults:
    value = settings.get("ssl", "off").lower()
    if value not in PG_TRUE_VALUES:
        return [
            (
                "postgresql.conf: ssl",
                "в файле не подтверждено включение TLS на стороне PostgreSQL; "
                "другие способы шифрования не проверены",
                config_line(settings, "ssl"),
            )
        ]
    return []


def check_password_encryption(settings: dict) -> CheckResults:
    configured = settings.get("password_encryption")
    if configured is None:
        return [
            (
                "postgresql.conf: password_encryption",
                "password_encryption не задан явно; действующее значение зависит "
                "от версии СУБД и источников настроек",
                None,
            )
        ]
    value = configured.lower()
    if value != "scram-sha-256":
        return [
            (
                "postgresql.conf: password_encryption",
                "Задан алгоритм, отличный от scram-sha-256",
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
                "log_statement не включает журналирование изменений схемы; "
                "другие источники аудита не проверены",
                config_line(settings, "log_statement"),
            )
        ]
    return []


def check_missing_statement_timeout(settings: dict) -> CheckResults:
    value = settings.get("statement_timeout", "0").strip()
    if not value or _ZERO_TIMEOUT.fullmatch(value):
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
    "P001": check_trust_auth,
    "P009": check_md5_auth,
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
