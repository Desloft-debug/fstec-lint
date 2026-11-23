"""Scoped negative and positive cases for explicit configuration evidence."""

from pathlib import Path

import pytest

from fstec_lint.checks.nginx_checks import check_no_rate_limit, check_no_rate_limit_strict
from fstec_lint.checks.postgres_checks import check_missing_statement_timeout
from fstec_lint.checks.sshd_checks import check_no_multifactor
from fstec_lint.parsers.nginx import parse_nginx
from fstec_lint.parsers.postgres import parse_postgresql_conf
from fstec_lint.parsers.sshd import parse_sshd_config


@pytest.mark.parametrize(
    ("timeout", "expected"), [("0 ms", True), ("0\tus", True), ("0.0 s", True), ("15 ms", False)]
)
def test_postgresql_timeout_unit_whitespace(tmp_path: Path, timeout: str, expected: bool) -> None:
    conf = tmp_path / "postgresql.conf"
    conf.write_text(f"statement_timeout = '{timeout}'\n")
    findings = check_missing_statement_timeout(parse_postgresql_conf(conf))
    assert bool(findings) is expected
    if expected:
        assert findings[0][2] == 1


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ("publickey,publickey", True),
        ("publickey,keyboard-interactive:pam", False),
        ("publickey,keyboard-interactive:pam publickey", True),
        ("publickey,keyboard-interactive:pam publickey,publickey", True),
    ],
)
def test_authentication_paths_require_distinct_methods(
    tmp_path: Path, options: str, expected: bool
) -> None:
    conf = tmp_path / "sshd_config"
    conf.write_text(f"AuthenticationMethods {options}\n")
    findings = check_no_multifactor(parse_sshd_config(conf))
    assert bool(findings) is expected
    if expected:
        assert findings[0][2] == 1


@pytest.mark.parametrize(
    ("parent", "first", "second", "legacy", "strict"),
    [
        ("", "limit_req zone=demo;", "return 204;", False, True),
        ("limit_req zone=demo;", "return 204;", "return 204;", False, False),
        ("limit_req zone=demo;", "limit_req_dry_run on;", "return 204;", False, True),
        ("", "return 204;", "return 204;", True, True),
    ],
)
def test_rate_limits_are_scoped_per_declared_route(
    tmp_path: Path, parent: str, first: str, second: str, legacy: bool, strict: bool
) -> None:
    cfg = tmp_path / "nginx.conf"
    cfg.write_text(
        "http {\n"
        "  limit_req_zone $binary_remote_addr zone=demo:1m rate=5r/s;\n"
        f"  {parent}\n"
        "  server {\n"
        f"    location /preview {{ {first} }}\n"
        f"    location / {{ {second} }}\n"
        "  }\n"
        "}\n"
    )
    nginx = parse_nginx(cfg)
    assert bool(check_no_rate_limit(nginx)) is legacy
    strict_findings = check_no_rate_limit_strict(nginx)
    assert bool(strict_findings) is strict
    if strict:
        assert len(strict_findings) == 1
        assert strict_findings[0][2] in {4, 5, 6}
