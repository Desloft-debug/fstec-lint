"""Проверки sshd_config. Все функции принимают dict из parse_sshd_config."""

from __future__ import annotations

from .base import CheckResult, config_line


def check_permit_root_login(settings: dict) -> list[CheckResult]:
    value = settings.get("permitrootlogin", "prohibit-password").lower()
    if value in ("yes", "without-password"):
        return [
            (
                "sshd_config: PermitRootLogin",
                f"PermitRootLogin {value} — вход root по SSH разрешён",
                config_line(settings, "permitrootlogin"),
            )
        ]
    return []


def check_password_authentication(settings: dict) -> list[CheckResult]:
    value = settings.get("passwordauthentication", "yes").lower()
    if value == "yes":
        return [
            (
                "sshd_config: PasswordAuthentication",
                "PasswordAuthentication yes — доступ по паролю разрешён "
                "вместо аутентификации по ключу",
                config_line(settings, "passwordauthentication"),
            )
        ]
    return []


def check_permit_empty_passwords(settings: dict) -> list[CheckResult]:
    value = settings.get("permitemptypasswords", "no").lower()
    if value == "yes":
        return [
            (
                "sshd_config: PermitEmptyPasswords",
                "PermitEmptyPasswords yes — вход с пустым паролем разрешён",
                config_line(settings, "permitemptypasswords"),
            )
        ]
    return []


def check_weak_protocol(settings: dict) -> list[CheckResult]:
    value = settings.get("protocol", "2")
    if "1" in value.split(","):
        return [
            (
                "sshd_config: Protocol",
                f"Protocol {value} — включён устаревший небезопасный SSH-1",
                config_line(settings, "protocol"),
            )
        ]
    return []


def check_x11_forwarding(settings: dict) -> list[CheckResult]:
    value = settings.get("x11forwarding", "no").lower()
    if value == "yes":
        return [
            (
                "sshd_config: X11Forwarding",
                "X11Forwarding yes — расширяет поверхность атаки без явной необходимости",
                config_line(settings, "x11forwarding"),
            )
        ]
    return []


def check_max_auth_tries(settings: dict) -> list[CheckResult]:
    value = settings.get("maxauthtries", "6")
    try:
        tries = int(value)
    except ValueError:
        return []
    if tries > 4:
        return [
            (
                "sshd_config: MaxAuthTries",
                f"MaxAuthTries {tries} — подбор пароля не ограничен разумным числом попыток",
                config_line(settings, "maxauthtries"),
            )
        ]
    return []


REGISTRY = {
    "S001": check_permit_root_login,
    "S002": check_password_authentication,
    "S003": check_permit_empty_passwords,
    "S004": check_weak_protocol,
    "S005": check_x11_forwarding,
    "S006": check_max_auth_tries,
}
