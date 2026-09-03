"""Проверки юнитов systemd. Все функции принимают dict из parse_systemd_unit
и читают секцию [Service]."""

from __future__ import annotations

from .base import CheckResult, config_line

# systemd считает истиной любое из этих написаний, не только 'true'.
# Проверять одно из них — значит ругаться на корректно закалённый юнит.
TRUE_VALUES = frozenset({"true", "yes", "on", "1"})


def _service(unit: dict) -> dict:
    return unit.get("Service", {}) or {}


def _is_true(service: dict, key: str) -> bool:
    return str(service.get(key, "")).strip().lower() in TRUE_VALUES


def check_runs_as_root(unit: dict) -> list[CheckResult]:
    service = _service(unit)
    # DynamicUser=yes — systemd сам выделяет сервису временный
    # непривилегированный uid, и статический User при этом не нужен:
    # такой юнит от root не работает.
    if _is_true(service, "DynamicUser"):
        return []
    user = service.get("User", "root")
    if user == "root" or not user:
        return [
            (
                "[Service]: User",
                "User не задан или равен root — процесс выполняется от root",
                config_line(service, "User"),
            )
        ]
    return []


def check_no_new_privileges(unit: dict) -> list[CheckResult]:
    service = _service(unit)
    if not _is_true(service, "NoNewPrivileges"):
        return [
            (
                "[Service]: NoNewPrivileges",
                "NoNewPrivileges не установлен в true — процесс может повысить "
                "привилегии через setuid-бинарники",
                config_line(service, "NoNewPrivileges"),
            )
        ]
    return []


def check_protect_system(unit: dict) -> list[CheckResult]:
    service = _service(unit)
    value = str(service.get("ProtectSystem", "")).strip().lower()
    if value not in ("full", "strict", "yes"):
        return [
            (
                "[Service]: ProtectSystem",
                "ProtectSystem не установлен в yes/full/strict — файловая система "
                "хоста доступна процессу на запись",
                config_line(service, "ProtectSystem"),
            )
        ]
    return []


def check_private_tmp(unit: dict) -> list[CheckResult]:
    service = _service(unit)
    if not _is_true(service, "PrivateTmp"):
        return [
            (
                "[Service]: PrivateTmp",
                "PrivateTmp не установлен в true — сервис делит /tmp с другими процессами",
                config_line(service, "PrivateTmp"),
            )
        ]
    return []


def check_protect_home(unit: dict) -> list[CheckResult]:
    service = _service(unit)
    # tmpfs — тоже защита: поверх /home монтируется пустая tmpfs,
    # домашние каталоги сервису не видны.
    value = str(service.get("ProtectHome", "")).strip().lower()
    if value not in ("true", "yes", "on", "1", "read-only", "tmpfs"):
        return [
            (
                "[Service]: ProtectHome",
                "ProtectHome не установлен — сервис может читать домашние каталоги пользователей",
                config_line(service, "ProtectHome"),
            )
        ]
    return []


REGISTRY = {
    "U001": check_runs_as_root,
    "U002": check_no_new_privileges,
    "U003": check_protect_system,
    "U004": check_private_tmp,
    "U005": check_protect_home,
}
