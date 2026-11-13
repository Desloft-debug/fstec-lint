"""Restored target acceptance via public engine; thresholds are project policy."""

import json

import pytest
from integration_helpers import cli, write

from fstec_lint import baseline
from fstec_lint.engine import discover_files, load_rules, scan

# Fixed positive/negative pairs, shared by the acceptance and baseline checks.
TARGETS = [
    (
        "C017",
        "compose.yaml",
        "services: {app: {logging: {driver: json-file}}}\n",
        "services: {app: {logging: {driver: syslog}}}\n",
    ),
    ("E001", ".env", "PASSWORD=SYNTHETIC_TEST_VALUE\n", "PASSWORD=${EXTERNAL}\n"),
    ("E002", ".env", "DEBUG=true\n", "DEBUG=false\n"),
    ("E003", ".env", "PGSSLMODE=disable\n", "PGSSLMODE=verify-full\n"),
    ("A001", "etc/login.defs", "PASS_MAX_DAYS 91\n", "PASS_MAX_DAYS 90\n"),
    ("A002", "etc/security/pwquality.conf", "minlen=7\nminclass=2\n", "minlen=8\nminclass=3\n"),
    ("A003", "etc/default/useradd", "INACTIVE=36\n", "INACTIVE=35\n"),
    ("R001", "etc/rsyslog.conf", "*.* /var/log/all\n", "*.* @@siem.invalid:514\n"),
    (
        "N001",
        "nginx/nginx.conf",
        "http { server { ssl_protocols TLSv1 TLSv1.2; } }\n",
        "http { server { ssl_protocols TLSv1.2 TLSv1.3; } }\n",
    ),
    (
        "N002",
        "nginx/nginx.conf",
        "http { server { autoindex on; } }\n",
        "http { server { autoindex off; } }\n",
    ),
    (
        "N003",
        "nginx/nginx.conf",
        "http { server { access_log off; } }\n",
        "http { server { access_log /var/log/nginx/access.log; } }\n",
    ),
    (
        "N004",
        "nginx/nginx.conf",
        "http { server { location / { } } }\n",
        "http { limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s; "
        "server { location / { limit_req zone=one; } } }\n",
    ),
    (
        "M001",
        "postfix/main.cf",
        "myhostname=mail.invalid\n",
        "smtpd_milters=inet:127.0.0.1:11332\n",
    ),
    (
        "S007",
        "sshd_config",
        "AuthenticationMethods any\n",
        "AuthenticationMethods publickey,keyboard-interactive\n",
    ),
    ("S008", "sshd_config", "LogLevel ERROR\n", "LogLevel INFO\n"),
]


@pytest.mark.parametrize("rule,name,bad,good", TARGETS, ids=[r[0] for r in TARGETS])
def test_each_restored_rule_positive_negative_and_baseline(tmp_path, rule, name, bad, good):
    assert rule in {r.id for r in load_rules()}, "rule must be registered, not merely parsed"
    path = write(tmp_path / name, bad)
    result = scan(tmp_path, select=[rule])
    assert not result.errors and result.findings, result
    assert {f.rule.id for f in result.findings} == {rule}
    assert all(f.file == str(path) for f in result.findings)
    saved = write(tmp_path / "known.json", baseline.render(result.findings))
    assert baseline.apply(result.findings, baseline.load(saved)) == ([], len(result.findings))
    assert not scan(tmp_path, select=[rule], ignore=[rule]).findings
    path.write_text(good, encoding="utf-8")
    clean = scan(tmp_path, select=[rule])
    assert not clean.errors and not clean.findings


@pytest.mark.parametrize("rule,name,bad,good", TARGETS, ids=[r[0] for r in TARGETS])
def test_restored_rule_cli_catalog_and_uz(tmp_path, capsys, rule, name, bad, good):
    path = write(tmp_path / name, bad)
    assert cli(["--list-rules", "--select", rule, "--format", "json"]) == 0
    assert {r["id"] for r in json.loads(capsys.readouterr().out)["rules"]} == {rule}
    for level in (1, 2, 3, 4):
        assert cli(["--list-rules", "--select", rule, "--uz", str(level), "--format", "json"]) == 0
        active = bool(json.loads(capsys.readouterr().out)["rules"])
        result = scan(path, select=[rule], uz=level)
        assert not result.errors and bool(result.findings) is active


@pytest.mark.parametrize(
    "name,target",
    [
        ("etc/login.defs", "login_defs"),
        ("etc/security/pwquality.conf", "pwquality"),
        ("etc/security/pwquality.conf.d/50-local.conf", "pwquality"),
        ("etc/rsyslog.conf", "rsyslog"),
        ("etc/default/useradd", "useradd_defaults"),
        ("nginx/nginx.conf", "nginx"),
        ("deploy/nginx/conf.d/site.conf", "nginx"),
        ("postfix/main.cf", "postfix_main"),
    ],
)
def test_contextual_discovery(tmp_path, name, target):
    path = write(tmp_path / name, "# synthetic\n")
    assert path in discover_files(tmp_path)[target]


@pytest.mark.parametrize(
    "name,target",
    [
        ("app/main.cf", "postfix_main"),
        ("scripts/useradd", "useradd_defaults"),
        ("app/conf.d/other.conf", "nginx"),
    ],
)
def test_generic_names_do_not_imply_target(tmp_path, name, target):
    path = write(tmp_path / name, "not a supported config\n")
    assert path not in discover_files(tmp_path)[target]


@pytest.mark.parametrize("rule,name,bad,good", TARGETS, ids=[r[0] for r in TARGETS])
def test_filters_apply_before_target_parser(tmp_path, monkeypatch, rule, name, bad, good):
    write(tmp_path / "examples" / name, bad)
    import fstec_lint.engine as engine

    def forbidden(*args, **kwargs):
        raise AssertionError("excluded target reached parsing")

    # Observe existing dispatch names; absent restored rules still fail in the rule test.
    for attr in list(vars(engine)):
        if attr.startswith("parse_") and callable(getattr(engine, attr)):
            monkeypatch.setattr(engine, attr, forbidden)
    for options in (
        {"ignore": [rule], "select": [rule]},
        {"select": ["D001"]},
        {"select": [rule], "exclude": ["examples"]},
        {"select": [rule], "production_only": True},
    ):
        result = scan(tmp_path, **options)
        assert not result.errors and not result.findings, result


@pytest.mark.parametrize("value,expected", [(None, True), ("90", False), ("91", True)])
def test_password_age_boundary(tmp_path, value, expected):
    path = write(tmp_path / "login.defs", "" if value is None else f"PASS_MAX_DAYS {value}\n")
    result = scan(path, select=["A001"])
    assert not result.errors and bool(result.findings) is expected


@pytest.mark.parametrize(
    "content,expected",
    [
        ("", True),
        ("minlen=8\nminclass=3\n", False),
        ("minlen=7\nminclass=3\n", True),
        ("minlen=8\nminclass=2\n", True),
        ("minlen=8\ndcredit=-1\nucredit=-1\nocredit=-1\n", False),
    ],
)
def test_password_complexity_boundaries(tmp_path, content, expected):
    path = write(tmp_path / "pwquality.conf", content)
    result = scan(path, select=["A002"])
    assert not result.errors and bool(result.findings) is expected


@pytest.mark.parametrize(
    "value,expected", [(None, True), (-1, True), (0, False), (35, False), (36, True)]
)
def test_post_expiration_account_lock_policy(tmp_path, value, expected):
    path = write(tmp_path / "default/useradd", "" if value is None else f"INACTIVE={value}\n")
    result = scan(path, select=["A003"])
    assert not result.errors and bool(result.findings) is expected


def test_pwquality_override_origin(tmp_path):
    # libpwquality reads sorted fragments first and the main config last.
    # An unrelated main key preserves the fragment's effective value and origin.
    write(tmp_path / "pwquality.conf", "minclass=3\n")
    override = write(tmp_path / "pwquality.conf.d/50-local.conf", "minlen=7\n")
    result = scan(tmp_path, select=["A002"])
    assert not result.errors and len(result.findings) == 1
    assert (result.findings[0].file, result.findings[0].line) == (str(override), 1)


@pytest.mark.parametrize(
    "rule,name,content,line",
    [
        ("A001", "login.defs", "PASS_MAX_DAYS 91", 2),
        ("A002", "pwquality.conf", "minlen=7\nminclass=2", 2),
        ("A003", "default/useradd", "INACTIVE=36", 2),
        ("N002", "nginx.conf", "http { server { autoindex on; } }", 2),
        ("S007", "sshd_config", "AuthenticationMethods any", 2),
        ("S008", "sshd_config", "LogLevel ERROR", 2),
    ],
)
def test_restored_source_locations_and_suppression(tmp_path, rule, name, content, line):
    path = write(tmp_path / name, "# comment\n" + content + "\n")
    result = scan(tmp_path, select=[rule])
    assert not result.errors and len(result.findings) == 1
    assert (result.findings[0].file, result.findings[0].line) == (str(path), line)
    path.write_text(f"# fstec-lint: ignore {rule}\n" + content + "\n", encoding="utf-8")
    result = scan(tmp_path, select=[rule])
    assert not result.errors and not result.findings and result.suppressed == 1


@pytest.mark.parametrize(
    "value,expected",
    [
        ("any", True),
        ("publickey", True),
        ("publickey,password publickey", True),
        ("publickey,keyboard-interactive", False),
        ("publickey,password publickey,keyboard-interactive", False),
    ],
)
def test_ssh_authentication_alternatives(tmp_path, value, expected):
    result = scan(
        write(tmp_path / "sshd_config", f"AuthenticationMethods {value}\n"), select=["S007"]
    )
    assert not result.errors and bool(result.findings) is expected


@pytest.mark.parametrize(
    "value,expected",
    [("INFO", False), ("VERBOSE", False), ("QUIET", True), ("FATAL", True), ("ERROR", True)],
)
def test_ssh_log_level(tmp_path, value, expected):
    result = scan(write(tmp_path / "sshd_config", f"LogLevel {value}\n"), select=["S008"])
    assert not result.errors and bool(result.findings) is expected
