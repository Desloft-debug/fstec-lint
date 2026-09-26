"""Правила 1.0.1: SSH (S007, S008), Compose (C017), login.defs, pwquality,
/etc/default/useradd, rsyslog, nginx и Postfix."""

from pathlib import Path

import pytest

from fstec_lint.checks import (
    compose_checks,
    linux_checks,
    nginx_checks,
    postfix_checks,
    sshd_checks,
)
from fstec_lint.engine import discover_files, scan
from fstec_lint.parsers.base import ConfigMap
from fstec_lint.parsers.linux import (
    parse_login_defs,
    parse_pwquality,
    parse_rsyslog,
    parse_useradd_defaults,
)
from fstec_lint.parsers.nginx import parse_nginx
from fstec_lint.parsers.postfix import parse_postfix_main


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _ids(root: Path) -> set[str]:
    return {f.rule.id for f in scan(root).findings}


# --- SSH -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "reported"),
    [
        (None, True),
        ("any", True),
        ("publickey", True),
        ("publickey,password publickey", True),
        ("publickey,keyboard-interactive", False),
        ("publickey,password publickey,keyboard-interactive", False),
    ],
)
def test_multifactor_authentication(value, reported):
    settings = ConfigMap()
    if value is not None:
        settings.set("authenticationmethods", value, 1)

    assert bool(sshd_checks.check_no_multifactor(settings)) is reported


@pytest.mark.parametrize(
    ("value", "reported"),
    [
        (None, False),
        ("INFO", False),
        ("VERBOSE", False),
        ("QUIET", True),
        ("SILENT", True),
        ("ERROR", True),
    ],
)
def test_failed_logins_logging(value, reported):
    settings = ConfigMap()
    if value is not None:
        settings.set("loglevel", value, 1)

    assert bool(sshd_checks.check_failed_logins_not_logged(settings)) is reported


# --- Compose -------------------------------------------------------------


@pytest.mark.parametrize(
    ("logging", "reported"),
    [
        (None, True),
        ({"driver": "json-file"}, True),
        ({"driver": "none"}, True),
        ({"driver": "syslog", "options": {"syslog-address": "tcp://siem:514"}}, False),
        ({"driver": "gelf"}, False),
        ({"driver": "fluentd"}, False),
    ],
)
def test_container_logs_centralized(logging, reported):
    svc = {"image": "x"} if logging is None else {"image": "x", "logging": logging}

    assert bool(compose_checks.check_logs_not_centralized({"services": {"app": svc}})) is reported


# --- login.defs и pwquality ------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reported"),
    [
        ("", True),
        ("PASS_MAX_DAYS\t99999\n", True),
        ("PASS_MAX_DAYS 180\n", True),
        ("PASS_MAX_DAYS 90\n", False),
        ("# PASS_MAX_DAYS 30\nPASS_MAX_DAYS 60\n", False),
        # getdef() из shadow-utils берёт последнее значение
        ("PASS_MAX_DAYS 60\nPASS_MAX_DAYS 120\n", True),
        ("PASS_MAX_DAYS 120\nPASS_MAX_DAYS 60\n", False),
    ],
)
def test_password_max_age(tmp_path, text, reported):
    settings = parse_login_defs(_write(tmp_path / "login.defs", text))

    assert bool(linux_checks.check_password_max_age(settings)) is reported


@pytest.mark.parametrize(
    ("text", "reported"),
    [
        ("", True),
        ("minlen = 12\n", True),
        ("minlen = 6\nminclass = 3\n", True),
        ("minlen = 10\nminclass = 3\n", False),
        ("minlen = 8\ndcredit = -1\nucredit = -1\nocredit = -1\n", False),
        ("# minlen = 14\nminlen=9\nminclass=4\n", False),
        # минимальная длина должна быть задана явно
        ("minclass = 3\n", True),
    ],
)
def test_password_complexity(tmp_path, text, reported):
    settings = parse_pwquality(_write(tmp_path / "pwquality.conf", text))

    assert bool(linux_checks.check_password_complexity(settings)) is reported


def test_pwquality_conf_d_overrides_main_file(tmp_path):
    _write(tmp_path / "pwquality.conf", "minlen = 12\nminclass = 3\n")
    _write(tmp_path / "pwquality.conf.d" / "50-local.conf", "minlen = 6\n")

    findings = [f for f in scan(tmp_path).findings if f.rule.id == "A002"]

    assert len(findings) == 1
    assert findings[0].file.endswith("50-local.conf")
    assert findings[0].line == 1


# --- rsyslog ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reported"),
    [
        ("*.info /var/log/messages\n", True),
        ("# *.* @@siem:514\n", True),
        ("*.* @@siem.local:514\n", False),
        ("auth,authpriv.* @10.0.0.5\n", False),
        ('action(type="omfwd" target="siem" port="514" protocol="tcp")\n', False),
        ('*.* action(\n  type="omrelp"\n  target="siem"\n  port="2514"\n)\n', False),
        ('action(type="omfile" file="/var/log/all")\n', True),
    ],
)
def test_rsyslog_forwarding(tmp_path, text, reported):
    config = parse_rsyslog(_write(tmp_path / "rsyslog.conf", text))

    assert bool(linux_checks.check_events_not_forwarded(config)) is reported


def test_rsyslog_forwarding_in_included_file(tmp_path):
    _write(tmp_path / "etc" / "rsyslog.conf", "$IncludeConfig /etc/rsyslog.d/*.conf\n")
    _write(tmp_path / "etc" / "rsyslog.d" / "90-siem.conf", "*.* @@siem:514\n")

    config = parse_rsyslog(tmp_path / "etc" / "rsyslog.conf")

    assert linux_checks.check_events_not_forwarded(config) == []
    assert config.forwards[0][1] == 1
    assert getattr(config.forwards[0][1], "file", "").endswith("90-siem.conf")


# --- nginx -----------------------------------------------------------------

SITE = """
http {
    limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/cert.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        location / { limit_req zone=one; }
    }
}
"""


def test_nginx_clean_config(tmp_path):
    config = parse_nginx(_write(tmp_path / "nginx.conf", SITE))

    for check in nginx_checks.REGISTRY.values():
        assert check(config) == []


@pytest.mark.parametrize(
    ("replace", "rule"),
    [
        ("ssl_protocols TLSv1.2 TLSv1.3;", "N001"),
        ("TLSv1.2 TLSv1.3", "N001"),
        ("location / {", "N002"),
        ("location / {", "N003"),
        ("limit_req zone=one;", "N004"),
    ],
)
def test_nginx_rules(tmp_path, replace, rule):
    variants = {
        ("ssl_protocols TLSv1.2 TLSv1.3;", "N001"): "",
        ("TLSv1.2 TLSv1.3", "N001"): "TLSv1 TLSv1.1 TLSv1.2",
        ("location / {", "N002"): "location / { autoindex on;",
        ("location / {", "N003"): "location / { access_log off;",
        ("limit_req zone=one;", "N004"): "",
    }
    text = SITE.replace(replace, variants[(replace, rule)])
    config = parse_nginx(_write(tmp_path / "nginx.conf", text))

    assert nginx_checks.REGISTRY[rule](config)


def test_nginx_include_and_line_of_included_file(tmp_path):
    _write(tmp_path / "nginx" / "nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
    _write(
        tmp_path / "nginx" / "conf.d" / "site.conf",
        "server {\n    listen 80;\n    autoindex on;\n}\n",
    )

    findings = [f for f in scan(tmp_path).findings if f.rule.id == "N002"]

    assert len(findings) == 1
    assert findings[0].file.endswith("site.conf")
    assert findings[0].line == 3


def test_nginx_site_without_main_config_is_scanned(tmp_path):
    _write(tmp_path / "deploy" / "nginx" / "conf.d" / "app.conf", "server { autoindex on; }\n")
    _write(tmp_path / "app" / "conf.d" / "other.conf", "not nginx\n")

    files = discover_files(tmp_path)["nginx"]

    assert [p.name for p in files] == ["app.conf"]
    assert "N002" in _ids(tmp_path)


def test_nginx_site_included_by_main_config_is_not_scanned_twice(tmp_path):
    _write(tmp_path / "nginx" / "nginx.conf", "http { include conf.d/*.conf; }\n")
    _write(tmp_path / "nginx" / "conf.d" / "app.conf", "server { autoindex on; }\n")

    findings = [f for f in scan(tmp_path).findings if f.rule.id == "N002"]

    assert len(findings) == 1


def test_nginx_quotes_and_comments(tmp_path):
    text = (
        'http { # comment ; {\n  log_format main "$remote_addr ; {x}";\n'
        "  server { access_log off; }\n}\n"
    )
    config = parse_nginx(_write(tmp_path / "nginx.conf", text))

    assert len(nginx_checks.check_access_log_off(config)) == 1
    assert nginx_checks.check_access_log_off(config)[0][2] == 3


def test_new_targets_are_discovered(tmp_path):
    _write(tmp_path / "etc" / "login.defs", "PASS_MAX_DAYS 99999\n")
    _write(tmp_path / "etc" / "security" / "pwquality.conf", "")
    _write(tmp_path / "etc" / "rsyslog.conf", "*.* /var/log/all\n")
    _write(tmp_path / "etc" / "default" / "useradd", "SHELL=/bin/sh\n")
    _write(tmp_path / "etc" / "postfix" / "main.cf", "myhostname = mail.test\n")

    assert {"A001", "A002", "A003", "M001", "R001"} <= _ids(tmp_path)


def test_generic_names_need_a_hint_in_the_path(tmp_path):
    _write(tmp_path / "scripts" / "useradd", "#!/bin/sh\n")
    _write(tmp_path / "app" / "main.cf", "key = value\n")

    files = discover_files(tmp_path)

    assert files["useradd_defaults"] == [] and files["postfix_main"] == []


# --- /etc/default/useradd -----------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reported"),
    [
        ("SHELL=/bin/sh\n", True),
        ("INACTIVE=-1\n", True),
        ("INACTIVE=180\n", True),
        ("# INACTIVE=30\n", True),
        ("INACTIVE=35\n", False),
        ("INACTIVE=0\n", False),
        ("INACTIVE=30\nINACTIVE=-1\n", True),
    ],
)
def test_inactive_accounts(tmp_path, text, reported):
    settings = parse_useradd_defaults(_write(tmp_path / "useradd", text))

    assert bool(linux_checks.check_inactive_accounts(settings)) is reported


# --- Postfix ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reported"),
    [
        ("myhostname = mail.test\n", True),
        ("# content_filter = smtp-amavis:[127.0.0.1]:10024\n", True),
        ("smtpd_milters =\n", True),
        ("content_filter = smtp-amavis:[127.0.0.1]:10024\n", False),
        ("smtpd_milters = inet:127.0.0.1:11332\n", False),
        ("smtpd_milters =\n    unix:/run/clamav-milter/clamav-milter.ctl\n", False),
        ("content_filter = amavis\ncontent_filter =\n", True),
    ],
)
def test_mail_filter(tmp_path, text, reported):
    settings = parse_postfix_main(_write(tmp_path / "main.cf", text))

    assert bool(postfix_checks.check_no_mail_filter(settings)) is reported
