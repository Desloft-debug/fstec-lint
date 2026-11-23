"""Проверки конфигурации nginx."""

from __future__ import annotations

from collections.abc import Iterator

from ..parsers.nginx import Directive, NginxConfig
from .base import CheckResults

WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _where(directive: Directive, parents: tuple[str, ...]) -> str:
    context = " > ".join(parents) or "main"
    return f"nginx {context}: {directive.name}"


def check_weak_tls(config: NginxConfig) -> CheckResults:
    findings = []
    for directive, parents in config.walk():
        if directive.name == "ssl_protocols":
            weak = [p for p in directive.args if p in WEAK_PROTOCOLS]
            if weak:
                findings.append(
                    (
                        _where(directive, parents),
                        f"в ssl_protocols указаны {', '.join(weak)}; "
                        "эффективные протоколы не проверены",
                        directive.line,
                    )
                )
    for parent, server in _server_contexts(config):
        marker = next((d for d in server.block or [] if _tls_indicator(d)), None)
        if marker is not None and not any(
            d.name == "ssl_protocols" for scope in (parent, server.block or []) for d in scope
        ):
            findings.append(
                (
                    "nginx server: ssl_protocols",
                    "при наличии признака TLS нет явного ssl_protocols в этом server "
                    "или его родительском блоке; версия и умолчания не проверены",
                    server.line,
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
        (
            _where(d, parents),
            "access_log off — журнал доступа nginx отключён в этом контексте; "
            "другие журналы не проверены",
            d.line,
        )
        for d, parents in config.walk()
        if d.name == "access_log" and d.args[:1] == ["off"]
    ]


def _server_contexts(
    config: NginxConfig, scope_names: frozenset[str] = frozenset({"http", "stream", "mail"})
) -> list[tuple[list[Directive], Directive]]:
    scopes = [config.directives]
    scopes.extend(
        d.block for d in config.directives if d.name in scope_names and d.block is not None
    )
    return [
        (scope, d) for scope in scopes for d in scope if d.name == "server" and d.block is not None
    ]


def _tls_indicator(directive: Directive) -> bool:
    return (directive.name == "listen" and "ssl" in directive.args) or (
        directive.name == "ssl_certificate"
    )


_LIMITS = ("limit_req", "limit_conn")
_LimitState = tuple[tuple[bool, bool], ...]


def _limit_scope(items: list[Directive], previous: _LimitState) -> _LimitState:
    states = []
    for name, (declared, dry_run) in zip(_LIMITS, previous, strict=True):
        declared = declared or any(d.name == name for d in items)
        local = next((d.args for d in items if d.name == f"{name}_dry_run"), None)
        if local is not None:
            dry_run = local == ["on"]
        states.append((declared, dry_run))
    return tuple(states)


def _has_active_limit(state: _LimitState) -> bool:
    return any(declared and not dry_run for declared, dry_run in state)


def _locations(
    items: list[Directive], previous: _LimitState
) -> Iterator[tuple[Directive, _LimitState]]:
    for directive in items:
        if directive.name == "location" and directive.block is not None:
            state = _limit_scope(directive.block, previous)
            yield directive, state
            yield from _locations(directive.block, state)


def _check_rate_limit(config: NginxConfig, *, strict: bool) -> CheckResults:
    matches = []
    for parent, server in _server_contexts(config, frozenset({"http"})):
        server_items = server.block or []
        inherited = _limit_scope(parent, ((False, False), (False, False)))
        server_state = _limit_scope(server_items, inherited)
        any_limit = _has_active_limit(server_state)
        uncovered = None
        if not any_limit or strict:
            for location, state in _locations(server_items, server_state):
                if _has_active_limit(state):
                    any_limit = True
                    if not strict:
                        break
                elif uncovered is None:
                    uncovered = location
        if not any_limit:
            matches.append(
                (
                    "nginx http server: limit_req",
                    "для этого server не обнаружен действующий в исходном файле "
                    "limit_req или limit_conn; покрытие маршрутов и внешние ограничения "
                    "не проверены",
                    server.line,
                )
            )
        elif strict and uncovered is not None:
            matches.append(
                (
                    "nginx http server: limit_req",
                    "для одного или нескольких объявленных location не обнаружен "
                    "действующий limit_req или limit_conn; внешние ограничения не проверены",
                    uncovered.line,
                )
            )
    return matches


def check_no_rate_limit(config: NginxConfig) -> CheckResults:
    return _check_rate_limit(config, strict=False)


def check_no_rate_limit_strict(config: NginxConfig) -> CheckResults:
    """Check each visible location; limits of sibling routes are not inherited."""
    return _check_rate_limit(config, strict=True)


REGISTRY = {
    "N001": check_weak_tls,
    "N002": check_autoindex,
    "N003": check_access_log_off,
    "N004": check_no_rate_limit,
}
