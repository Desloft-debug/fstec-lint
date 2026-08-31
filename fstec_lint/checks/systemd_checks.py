"""Проверки юнитов systemd. Все функции принимают dict из parse_systemd_unit
и читают секцию [Service]."""

from __future__ import annotations


def _service(unit: dict) -> dict:
    return unit.get("Service", {}) or {}


def check_runs_as_root(unit: dict) -> list[tuple[str, str]]:
    service = _service(unit)
    user = service.get("User", "root")
    if user == "root" or not user:
        return [("[Service]: User", "User не задан или равен root — процесс выполняется от root")]
    return []


def check_no_new_privileges(unit: dict) -> list[tuple[str, str]]:
    value = _service(unit).get("NoNewPrivileges", "no").lower()
    if value != "true":
        return [
            (
                "[Service]: NoNewPrivileges",
                "NoNewPrivileges не установлен в true — процесс может повысить "
                "привилегии через setuid-бинарники",
            )
        ]
    return []


def check_protect_system(unit: dict) -> list[tuple[str, str]]:
    value = _service(unit).get("ProtectSystem", "").lower()
    if value not in ("full", "strict", "yes"):
        return [
            (
                "[Service]: ProtectSystem",
                "ProtectSystem не установлен в full/strict — файловая система "
                "хоста доступна процессу на запись",
            )
        ]
    return []


def check_private_tmp(unit: dict) -> list[tuple[str, str]]:
    value = _service(unit).get("PrivateTmp", "no").lower()
    if value != "true":
        return [
            (
                "[Service]: PrivateTmp",
                "PrivateTmp не установлен в true — сервис делит /tmp с другими процессами",
            )
        ]
    return []


def check_protect_home(unit: dict) -> list[tuple[str, str]]:
    value = _service(unit).get("ProtectHome", "no").lower()
    if value not in ("true", "yes", "read-only"):
        return [
            (
                "[Service]: ProtectHome",
                "ProtectHome не установлен — сервис может читать домашние каталоги пользователей",
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
