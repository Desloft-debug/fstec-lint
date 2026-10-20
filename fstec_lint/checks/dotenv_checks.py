"""Проверки .env: в результатах есть только имена переменных, без значений."""

from __future__ import annotations

import re
from collections.abc import Callable

from ..parsers.dotenv import EnvEntry, EnvFile
from .base import CheckResults

SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)(?:_|$)",
    re.IGNORECASE,
)
REFERENCE_RE = re.compile(
    r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?:(?::?\?)[^{}]*|:?\-)?\})"
)
URL_PASSWORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:([^@/\s]+)@")
TRUTHY = frozenset({"1", "true", "yes", "on"})


def _literal(value: str, interpolate: bool) -> bool:
    return bool(value.strip()) and not (interpolate and REFERENCE_RE.fullmatch(value))


def _secret(entry: EnvEntry) -> bool:
    if entry.key.upper().endswith(("_FILE", "_FILENAME")):
        return False
    if SECRET_KEY_RE.search(entry.key) and _literal(entry.value, entry.interpolate):
        return True
    return any(
        _literal(match.group(1), entry.interpolate)
        for match in URL_PASSWORD_RE.finditer(entry.value)
    )


def check_plaintext_secrets(data: EnvFile) -> CheckResults:
    return [
        (
            f"variable:{entry.key}",
            f"переменная {entry.key} содержит секрет в открытом виде",
            entry.line,
        )
        for entry in data.entries
        if _secret(entry)
    ]


def check_debug(data: EnvFile) -> CheckResults:
    return [
        (f"variable:{entry.key}", f"переменная {entry.key} включает режим отладки", entry.line)
        for entry in data.entries
        if (entry.key.upper() == "DEBUG" or entry.key.upper().endswith("_DEBUG"))
        and entry.value.strip().lower() in TRUTHY
    ]


def check_tls_disabled(data: EnvFile) -> CheckResults:
    findings = []
    for entry in data.entries:
        key, value = entry.key, entry.value
        if (
            (key == "NODE_TLS_REJECT_UNAUTHORIZED" and value == "0")
            or key == "GIT_SSL_NO_VERIFY"
            or (key == "PGSSLMODE" and value == "disable")
        ):
            findings.append(
                (
                    f"variable:{entry.key}",
                    f"переменная {entry.key} отключает защиту TLS или проверку сертификата",
                    entry.line,
                )
            )
    return findings


REGISTRY: dict[str, Callable[[EnvFile], CheckResults]] = {
    "E001": check_plaintext_secrets,
    "E002": check_debug,
    "E003": check_tls_disabled,
}
