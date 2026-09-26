"""Проверки конфигурации nginx."""

from __future__ import annotations

from ..parsers.nginx import Directive, NginxConfig
from .base import CheckResults

WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _where(directive: Directive, parents: tuple[str, ...]) -> str:
    context = " > ".join(parents) or "main"
    return f"nginx {context}: {directive.name}"


def check_weak_tls(config: NginxConfig) -> CheckResults:
    findings = []
    protocols = []
    uses_tls = None
    for directive, parents in config.walk():
        if directive.name == "ssl_protocols":
            protocols.append(directive)
            weak = [p for p in directive.args if p in WEAK_PROTOCOLS]
            if weak:
                findings.append(
                    (
                        _where(directive, parents),
                        f"ssl_protocols разрешает {', '.join(weak)}",
                        directive.line,
                    )
                )
        elif uses_tls is None and (
            (directive.name == "listen" and "ssl" in directive.args)
            or directive.name == "ssl_certificate"
        ):
            uses_tls = directive
    if uses_tls is not None and not protocols:
        findings.append(
            (
                "nginx: ssl_protocols",
                "ssl_protocols не задан: до nginx 1.23.4 по умолчанию разрешены TLSv1 и TLSv1.1",
                uses_tls.line,
            )
        )
    return findings


def check_autoindex(config: NginxConfig) -> CheckResults:
    return [
        (_where(d, parents), "autoindex on — выводится список файлов каталога", d.line)
        for d, parents in config.walk()
        if d.name == "autoindex" and d.args[:1] == ["on"]
    ]


def check_access_log_off(config: NginxConfig) -> CheckResults:
    return [
        (_where(d, parents), "access_log off — обращения к веб-серверу не регистрируются", d.line)
        for d, parents in config.walk()
        if d.name == "access_log" and d.args[:1] == ["off"]
    ]


def check_no_rate_limit(config: NginxConfig) -> CheckResults:
    servers = [d for d, _ in config.walk() if d.name == "server" and d.block is not None]
    if not servers:
        return []
    if any(d.name in ("limit_req", "limit_conn") for d, _ in config.walk()):
        return []
    return [
        (
            "nginx http: limit_req",
            "не задано ограничение частоты запросов или числа соединений (limit_req, limit_conn)",
            servers[0].line,
        )
    ]


REGISTRY = {
    "N001": check_weak_tls,
    "N002": check_autoindex,
    "N003": check_access_log_off,
    "N004": check_no_rate_limit,
}
