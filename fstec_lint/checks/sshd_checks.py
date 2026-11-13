"""Проверки sshd_config. Все функции принимают dict из parse_sshd_config."""

from __future__ import annotations

from collections.abc import Iterator

from .base import CheckResults, config_line


def _values(settings: dict, key: str, default: str) -> Iterator[tuple[str, str, int | None]]:
    """Значение директивы в глобальной секции и в каждом Match-блоке.

    В глобальной секции подставляется умолчание sshd: отсутствие
    директивы не равно безопасному значению. В Match-блоке судим только
    о явно заданном — неуказанное наследуется сверху и уже проверено.
    """
    yield "", str(settings.get(key, default)), config_line(settings, key)
    for block in getattr(settings, "matches", []):
        if key in block.settings:
            yield (
                f" (Match {block.criteria})",
                str(block.settings[key]),
                block.settings.line(key),
            )


def check_permit_root_login(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "permitrootlogin", "prohibit-password"):
        value = raw.strip().lower()
        if value == "yes":
            findings.append(
                (
                    f"sshd_config: PermitRootLogin{scope}",
                    f"PermitRootLogin {value} — вход root по SSH разрешён",
                    line,
                )
            )
    return findings


def check_password_authentication(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "passwordauthentication", "yes"):
        if raw.lower() == "yes":
            findings.append(
                (
                    f"sshd_config: PasswordAuthentication{scope}",
                    "PasswordAuthentication yes — доступ по паролю разрешён "
                    "вместо аутентификации по ключу",
                    line,
                )
            )
    return findings


def check_permit_empty_passwords(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "permitemptypasswords", "no"):
        if raw.lower() == "yes":
            findings.append(
                (
                    f"sshd_config: PermitEmptyPasswords{scope}",
                    "PermitEmptyPasswords yes — вход с пустым паролем разрешён",
                    line,
                )
            )
    return findings


def check_weak_protocol(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "protocol", "2"):
        if "1" in (part.strip() for part in raw.split(",")):
            findings.append(
                (
                    f"sshd_config: Protocol{scope}",
                    "Указан SSH-1; версия сервера неизвестна. "
                    "OpenSSH 7.4 и новее не поддерживает серверный SSH-1",
                    line,
                )
            )
    return findings


def check_x11_forwarding(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "x11forwarding", "no"):
        if raw.lower() == "yes":
            findings.append(
                (
                    f"sshd_config: X11Forwarding{scope}",
                    "X11Forwarding yes — расширяет поверхность атаки без явной необходимости",
                    line,
                )
            )
    return findings


def check_max_auth_tries(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "maxauthtries", "6"):
        try:
            tries = int(raw)
        except ValueError:
            continue
        if tries > 4:
            findings.append(
                (
                    f"sshd_config: MaxAuthTries{scope}",
                    f"MaxAuthTries {tries} — подбор пароля не ограничен разумным числом попыток",
                    line,
                )
            )
    return findings


def check_no_multifactor(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "authenticationmethods", "any"):
        lists = raw.split()
        # Каждый список через пробел — отдельный допустимый путь входа.
        # Список из одного метода означает вход с одним фактором.
        single = [item for item in lists if len(item.split(",")) < 2]
        if raw.strip().lower() == "any" or single:
            detail = (
                "AuthenticationMethods any допускает один метод; факторы и PAM не проверены"
                if raw.strip().lower() == "any"
                else "AuthenticationMethods допускает путь с одним методом; "
                "факторы и PAM не проверены"
            )
            findings.append((f"sshd_config: AuthenticationMethods{scope}", detail, line))
    return findings


# SILENT — синоним QUIET, так его выводит sshd -T.
QUIET_LOG_LEVELS = frozenset({"quiet", "silent", "fatal", "error"})


def check_failed_logins_not_logged(settings: dict) -> CheckResults:
    findings = []
    for scope, raw, line in _values(settings, "loglevel", "INFO"):
        if raw.strip().lower() in QUIET_LOG_LEVELS:
            findings.append(
                (
                    f"sshd_config: LogLevel{scope}",
                    "LogLevel ограничивает обычный журнал sshd; "
                    "другие источники событий не проверены",
                    line,
                )
            )
    return findings


REGISTRY = {
    "S007": check_no_multifactor,
    "S008": check_failed_logins_not_logged,
    "S001": check_permit_root_login,
    "S002": check_password_authentication,
    "S003": check_permit_empty_passwords,
    "S004": check_weak_protocol,
    "S005": check_x11_forwarding,
    "S006": check_max_auth_tries,
}
