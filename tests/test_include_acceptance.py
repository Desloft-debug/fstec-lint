"""Include regressions, using public CLI/engine and independent inputs."""

import json
from pathlib import Path

import pytest
from integration_helpers import cli, write

from fstec_lint.engine import scan


@pytest.mark.parametrize(
    "directive",
    [
        "$IncludeConfig rsyslog.d/*.conf\n",
        'include(file="rsyslog.d/*.conf")\n',
        "$IncludeConfig rsyslog.d/forward.conf\n",
    ],
)
def test_rsyslog_active_include_is_not_a_block_comment(tmp_path, capsys, directive):
    write(tmp_path / "rsyslog.conf", directive)
    write(tmp_path / "rsyslog.d/forward.conf", "*.* @@collector.invalid:514\n")
    assert cli([str(tmp_path), "--select", "R001", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == [] and not captured.err


@pytest.mark.parametrize(
    "text,expected",
    [
        ('/* include(file="missing.conf") */\n', True),
        ('# include(file="missing.conf")\n', True),
        ('set $x="/* # */ ( )";\n', True),
        ('action(\n type="omfwd"\n target="collector.invalid"\n)\n', False),
        ('action(type="omfwd" target="collector.invalid") # /* comment\n', False),
        ('/* hidden */ action(type="omfwd" target="collector.invalid")\n', False),
        ('set $x="line one\n# /* still a string */";\n', True),
    ],
)
def test_rsyslog_comment_neighbors(tmp_path, text, expected):
    result = scan(write(tmp_path / "rsyslog.conf", text), select=["R001"])
    assert not result.errors
    assert bool(result.findings) is expected


@pytest.mark.parametrize("text", ["/* unclosed", 'action(type="omfwd"', 'set $x="unclosed'])
def test_rsyslog_incomplete_input_is_partial_and_private(tmp_path, capsys, text):
    secret = "TEST_SYNTHETIC_SECRET_c91a"
    path = write(tmp_path / "rsyslog.conf", text + secret)
    assert cli([str(path), "--select", "R001", "--fail-on", "none"]) == 3
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("real_comment", [False, True])
@pytest.mark.parametrize("location", ["conf.d/site.conf", "sites-enabled/site"])
def test_nginx_included_quote_and_comment_origin(tmp_path, real_comment, location):
    write(tmp_path / "nginx/nginx.conf", f"http {{ include {location}; }}\n")
    marker = "# fstec-lint: ignore N002"
    prefix = marker if real_comment else f'set $x "escaped \\" {marker}";'
    origin = write(tmp_path / "nginx" / location, f"server {{\n{prefix}\nautoindex on;\n}}\n")
    result = scan(tmp_path, select=["N002"])
    assert not result.errors
    assert len(result.findings) == (0 if real_comment else 1)
    if not real_comment:
        assert (result.findings[0].file, result.findings[0].line) == (str(origin), 3)


def test_nginx_conf_d_backup_not_in_active_include(tmp_path):
    # OLD public README promises conf.d/*.conf, distinct from sites-enabled/*.
    write(tmp_path / "nginx/nginx.conf", "http { include conf.d/*.conf; }\n")
    write(tmp_path / "nginx/conf.d/site.conf", "server { autoindex off; }\n")
    write(tmp_path / "nginx/conf.d/site.conf.bak", "server { autoindex on; }\n")
    result = scan(tmp_path, select=["N002"])
    assert not result.errors and not result.findings


@pytest.mark.parametrize("weak_last", [False, True])
@pytest.mark.parametrize("main", [False, True])
def test_pwquality_sorted_fragments_and_main_precedence(tmp_path, weak_last, main):
    root = tmp_path / "security"
    weak, strong = "minlen=7\nminclass=2\n", "minlen=16\nminclass=4\n"
    write(root / "pwquality.conf.d/20.conf", weak if weak_last else strong)
    write(root / "pwquality.conf.d/10.conf", strong if weak_last else weak)
    winner = root / "pwquality.conf.d/20.conf"
    expected = weak_last
    if main:
        winner = write(root / "pwquality.conf", strong if weak_last else weak)
        expected = not weak_last
    result = scan(tmp_path, select=["A002"])
    assert not result.errors and bool(result.findings) is expected
    if expected:
        assert len(result.findings) == 1 and result.findings[0].file == str(winner)


def test_pwquality_winning_fragment_suppression_and_explicit_selection(tmp_path):
    root = tmp_path / "pwquality.conf.d"
    first = write(root / "10.conf", "minlen=16\nminclass=4\n")
    write(root / "20.conf", "# fstec-lint: ignore A002\nminlen=7\nminclass=2\n")
    result = scan(tmp_path, select=["A002"])
    assert not result.errors and not result.findings and result.suppressed == 1
    explicit = scan(first, select=["A002"])
    assert not explicit.errors and not explicit.findings


@pytest.mark.parametrize(
    "body,missing",
    [
        ("FROM alpine:3.20\nHEALTHCHECK CMD true\nHEALTHCHECK NONE\n", True),
        ("FROM alpine:3.20\nHEALTHCHECK NONE\nHEALTHCHECK CMD true\n", False),
        ("FROM alpine:3.20 AS base\nHEALTHCHECK CMD true\nFROM base\n", False),
        ("FROM alpine:3.20 AS base\nHEALTHCHECK CMD true\nFROM alpine:3.20\n", True),
        ("FROM alpine:3.20 AS base\nHEALTHCHECK CMD true\nFROM base\nHEALTHCHECK NONE\n", True),
    ],
)
def test_d006_final_stage_and_last_instruction(tmp_path, body, missing):
    result = scan(write(tmp_path / "Dockerfile", body), select=["D006"])
    assert not result.errors and bool(result.findings) is missing


def test_sarif_unicode_path_oracle_roundtrip(tmp_path):
    from urllib.parse import unquote, urlsplit

    from integration_helpers import displayed_uri

    path = tmp_path / "Проверка & имя.conf"
    uri = displayed_uri(path)
    assert " " not in uri and "&" not in uri
    decoded = unquote(urlsplit(uri).path)
    if Path().anchor == "" and len(decoded) > 2 and decoded[2] == ":":
        decoded = decoded[1:]
    assert Path(decoded) == path
