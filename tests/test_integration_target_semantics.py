"""Supplement restored parser context and include contracts without private algorithms."""

from pathlib import Path

import pytest
from integration_helpers import displayed_path, write

from fstec_lint.engine import scan
from fstec_lint.models import Finding


@pytest.mark.parametrize("inside_cwd", [False, True])
def test_report_path_contract_for_internal_and_external_temp(tmp_path, monkeypatch, inside_cwd):
    from fstec_lint.engine import load_rules

    path = write(tmp_path / "selected/compose.yaml", "services: {}\n")
    if inside_cwd:
        monkeypatch.chdir(tmp_path)
        expected = str(Path("selected") / "compose.yaml")
    else:
        other = tmp_path / "other"
        other.mkdir()
        monkeypatch.chdir(other)
        expected = str(path)
    finding = Finding(load_rules()[0], str(path), "safe", "safe", 1)
    assert finding.relative_file() == displayed_path(path) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("PASS_MAX_DAYS 60\nPASS_MAX_DAYS 120\n", True),
        ("PASS_MAX_DAYS 120\nPASS_MAX_DAYS 60\n", False),
    ],
)
def test_login_defs_last_value(tmp_path, text, expected):
    result = scan(write(tmp_path / "login.defs", text), select=["A001"])
    assert not result.errors and bool(result.findings) is expected


@pytest.mark.parametrize(
    "forward",
    [
        "*.* @@siem.invalid:514\n",
        'action(type="omfwd" target="siem.invalid" port="514" protocol="tcp")\n',
        '*.* action(\n type="omrelp"\n target="siem.invalid"\n port="2514"\n)\n',
    ],
)
def test_rsyslog_forwarding_syntax(tmp_path, forward):
    result = scan(write(tmp_path / "rsyslog.conf", forward), select=["R001"])
    assert not result.errors and not result.findings


def test_rsyslog_contained_include(tmp_path):
    write(tmp_path / "rsyslog.conf", "$IncludeConfig rsyslog.d/*.conf\n")
    write(tmp_path / "rsyslog.d/90-forward.conf", "*.* @@siem.invalid:514\n")
    result = scan(tmp_path, select=["R001"])
    assert not result.errors and not result.findings


def test_nginx_include_origin_suppression_and_no_duplicates(tmp_path):
    write(tmp_path / "nginx/nginx.conf", "http { include conf.d/*.conf; }\n")
    path = write(tmp_path / "nginx/conf.d/site.conf", "server {\n autoindex on;\n}\n")
    result = scan(tmp_path, select=["N002"])
    assert not result.errors and len(result.findings) == 1
    assert (result.findings[0].file, result.findings[0].line) == (str(path), 2)
    path.write_text("server {\n autoindex on; # fstec-lint: ignore N002\n}\n", encoding="utf-8")
    result = scan(tmp_path, select=["N002"])
    assert not result.errors and not result.findings and result.suppressed == 1


def test_nginx_quoted_delimiters_do_not_change_scope(tmp_path):
    path = write(
        tmp_path / "nginx.conf",
        "http { # comment ; {\n"
        'log_format main "$remote_addr ; {x}";\nserver { access_log off; }\n}\n',
    )
    result = scan(path, select=["N003"])
    assert not result.errors and len(result.findings) == 1
    assert result.findings[0].line == 3


@pytest.mark.parametrize(
    "content,expected",
    [
        ("content_filter = smtp-amavis:[127.0.0.1]:10024\n", False),
        ("smtpd_milters =\n unix:/run/synthetic-milter.sock\n", False),
        ("content_filter = amavis\ncontent_filter =\n", True),
        ("# content_filter = amavis\n", True),
    ],
)
def test_postfix_filter_syntax(tmp_path, content, expected):
    result = scan(write(tmp_path / "postfix/main.cf", content), select=["M001"])
    assert not result.errors and bool(result.findings) is expected


@pytest.mark.parametrize(
    "rule,name,bad",
    [
        ("E002", ".env", "PASSWORD='unterminated"),
        ("N002", "nginx.conf", "http { server {"),
    ],
)
def test_unselected_targets_are_not_parsed_after_uz(tmp_path, monkeypatch, rule, name, bad):
    import fstec_lint.engine as engine
    from fstec_lint.engine import filter_by_uz, load_rules

    rule_obj = next(r for r in load_rules() if r.id == rule)
    inactive_levels = [n for n in (1, 2, 3, 4) if not filter_by_uz([rule_obj], n)]
    # E002 is absent at UZ4 under the restored policy.
    if rule == "E002":
        assert 4 in inactive_levels
    write(tmp_path / name, bad)
    for level in inactive_levels:

        def forbidden(*args, **kwargs):
            raise AssertionError("UZ-excluded target parsed")

        for attr in list(vars(engine)):
            if attr.startswith("parse_") and callable(getattr(engine, attr)):
                monkeypatch.setattr(engine, attr, forbidden)
        result = scan(tmp_path, select=[rule], uz=level)
        assert not result.errors and not result.findings
