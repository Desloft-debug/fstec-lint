"""Restored producers must not expose arbitrary config values through findings.

All markers are synthetic. The restored scanner, not a mock Finding, produces data.
"""

import io
import json
import zipfile
from dataclasses import asdict

import pytest
from integration_helpers import cli, write

from fstec_lint import baseline
from fstec_lint.engine import scan

MARKER = "SYNTHETIC_TEST_RESTORED_SECRET_6f21"
PRODUCERS = [
    ("A001", "login.defs", f"PASS_MAX_DAYS {MARKER}\n"),
    ("A002", "pwquality.conf", f"minlen={MARKER}\nminclass=1\n"),
    ("A003", "default/useradd", f"INACTIVE={MARKER}\n"),
    ("R001", "rsyslog.conf", f"# {MARKER}\n*.* /var/log/all\n"),
    (
        "C017",
        "compose.yaml",
        "services: {app: {logging: {driver: json-file, options: {password: " + MARKER + "}}}}\n",
    ),
    ("E001", ".env", f"DATABASE_URL=postgres://user:{MARKER}@host.invalid/app\n"),
    ("E002", ".env", f"DEBUG=true # {MARKER}\n"),
    ("E003", ".env", f"PGSSLMODE=disable # {MARKER}\n"),
    (
        "N001",
        "nginx.conf",
        f'http {{ server {{ ssl_protocols TLSv1 TLSv1.2; set $synthetic "{MARKER}"; }} }}\n',
    ),
    ("N002", "nginx.conf", f'http {{ server {{ autoindex on; set $x "{MARKER}"; }} }}\n'),
    ("N003", "nginx.conf", f'http {{ server {{ access_log off; set $x "{MARKER}"; }} }}\n'),
    ("N004", "nginx.conf", f'http {{ server {{ location / {{ set $x "{MARKER}"; }} }} }}\n'),
    ("M001", "postfix/main.cf", f"myhostname={MARKER}\n"),
    ("S007", "sshd_config", f"AuthenticationMethods any # {MARKER}\n"),
    ("S008", "sshd_config", f"LogLevel ERROR # {MARKER}\n"),
]


@pytest.mark.parametrize("rule,name,content", PRODUCERS, ids=[p[0] for p in PRODUCERS])
@pytest.mark.parametrize("fmt", ["text", "json", "html", "sarif", "passport", "docx"])
def test_all_restored_producers_are_private(tmp_path, capsys, rule, name, content, fmt):
    assert MARKER in content
    path = write(tmp_path / name, content)
    result = scan(path, select=[rule])
    assert not result.errors and result.findings
    for finding in result.findings:
        assert finding.rule.id == rule
        assert MARKER not in json.dumps(asdict(finding)) + repr(finding) + finding.fingerprint()
    assert MARKER not in baseline.render(result.findings)
    output = tmp_path / f"report.{fmt}"
    assert (
        cli([str(path), "--select", rule, "--format", fmt, "-o", str(output), "--fail-on", "none"])
        == 0
    )
    data = output.read_bytes()
    if fmt == "docx":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert all(MARKER.encode() not in archive.read(n) for n in archive.namelist())
    else:
        assert MARKER.encode() not in data
    captured = capsys.readouterr()
    assert MARKER not in captured.out + captured.err


@pytest.mark.parametrize(
    "name,content,rule",
    [
        (".env", f"PASSWORD='{MARKER}", "E001"),
        ("nginx.conf", f'http {{ server {{ set $x "{MARKER}', "N002"),
    ],
)
def test_restored_parser_diagnostics_are_private(tmp_path, capsys, name, content, rule):
    path = write(tmp_path / name, content)
    result = scan(path, select=[rule])
    assert result.errors and MARKER not in repr(result.errors)
    assert cli([str(path), "--select", rule, "--fail-on", "none"]) == 3
    captured = capsys.readouterr()
    assert MARKER not in captured.out + captured.err and "Traceback" not in captured.err


def test_dotenv_secret_rotation_does_not_change_identity(tmp_path):
    path = write(tmp_path / ".env", f"PASSWORD={MARKER}\n")
    first = scan(path, select=["E001"])
    assert not first.errors and len(first.findings) == 1
    path.write_text("PASSWORD=SYNTHETIC_ROTATED_SECRET\n", encoding="utf-8")
    second = scan(path, select=["E001"])
    assert not second.errors and len(second.findings) == 1
    assert first.findings[0].fingerprint() == second.findings[0].fingerprint()
