"""Проверки login.defs, pwquality.conf, /etc/default/useradd и rsyslog.conf."""

from __future__ import annotations

from ..parsers.linux import RsyslogConfig
from .base import CheckResults, config_line

MAX_PASSWORD_DAYS = 90
# Дней после истечения пароля до блокировки учётной записи (STIG — 35).
MAX_INACTIVE_DAYS = 35
MIN_PASSWORD_LENGTH = 8
MIN_CHAR_CLASSES = 3


def _int(value: object, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def check_password_max_age(settings: dict) -> CheckResults:
    raw = settings.get("PASS_MAX_DAYS")
    days = _int(raw, 99999)
    if raw is None or days < 0 or days > MAX_PASSWORD_DAYS:
        detail = (
            "PASS_MAX_DAYS не задан — срок действия пароля не ограничен"
            if raw is None
            else f"PASS_MAX_DAYS {raw} — пароль действует дольше {MAX_PASSWORD_DAYS} дней"
        )
        return [("login.defs: PASS_MAX_DAYS", detail, config_line(settings, "PASS_MAX_DAYS"))]
    return []


def check_password_complexity(settings: dict) -> CheckResults:
    problems = []
    if "minlen" not in settings:
        # Умолчание libpwquality (9) требованию соответствует, но политика
        # не зафиксирована в конфигурации и может смениться с версией пакета.
        problems.append("minlen не задан явно")
    minlen = _int(settings.get("minlen"), MIN_PASSWORD_LENGTH)
    if minlen < MIN_PASSWORD_LENGTH:
        problems.append(f"minlen {minlen} меньше {MIN_PASSWORD_LENGTH}")
    # Класс символов обязателен, если задан minclass или отрицательный *credit.
    credits = ("dcredit", "ucredit", "lcredit", "ocredit")
    required = sum(1 for key in credits if _int(settings.get(key), 0) < 0)
    classes = max(_int(settings.get("minclass"), 0), required)
    if classes < MIN_CHAR_CLASSES:
        problems.append(f"обязательных классов символов {classes}, нужно {MIN_CHAR_CLASSES}")
    if not problems:
        return []
    line = config_line(settings, "minlen") or config_line(settings, "minclass")
    return [("pwquality.conf", "; ".join(problems), line)]


def check_events_not_forwarded(config: RsyslogConfig) -> CheckResults:
    if config.forwards:
        return []
    return [
        (
            "rsyslog: пересылка событий",
            "нет правила пересылки событий на удалённый сервер (@@host, omfwd, omrelp)",
            None,
        )
    ]


def check_inactive_accounts(settings: dict) -> CheckResults:
    raw = settings.get("INACTIVE")
    days = _int(raw, -1)
    if raw is not None and 0 <= days <= MAX_INACTIVE_DAYS:
        return []
    if raw is None:
        detail = "INACTIVE не задан — учётная запись с истёкшим паролем не блокируется"
    elif days < 0:
        detail = f"INACTIVE={raw} — блокировка неиспользуемых учётных записей отключена"
    else:
        detail = (
            f"INACTIVE={raw} — учётная запись блокируется позже чем через {MAX_INACTIVE_DAYS} дней"
        )
    return [("useradd: INACTIVE", detail, config_line(settings, "INACTIVE"))]


LOGIN_DEFS_REGISTRY = {"A001": check_password_max_age}
USERADD_REGISTRY = {"A003": check_inactive_accounts}
PWQUALITY_REGISTRY = {"A002": check_password_complexity}
RSYSLOG_REGISTRY = {"R001": check_events_not_forwarded}
