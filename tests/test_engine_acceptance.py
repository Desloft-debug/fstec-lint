"""Public-engine regressions. No xfail of known product defects.

Policy oracles: checked-in rule YAML/README; pwquality precedence is based on
libpwquality 1.4.5 settings.c, pwquality_read_config (fragments before main).
"""

from pathlib import Path

import pytest

from fstec_lint.engine import scan


def put(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize(
    "name,text,rule",
    [
        ("nginx/conf.d/site.conf", "server { autoindex on; }\n", "N002"),
        ("security/pwquality.conf.d/50-local.conf", "minlen=7\nminclass=2\n", "A002"),
    ],
)
def test_standalone_fragments(tmp_path, explicit, name, text, rule):
    path = put(tmp_path, name, text)
    result = scan(path if explicit else tmp_path, select=[rule])
    assert not result.errors
    assert [f.rule.id for f in result.findings] == [rule]
    assert result.findings[0].file == str(path)


@pytest.mark.parametrize("weak_main", [False, True])
def test_pwquality_main_has_final_precedence(tmp_path, weak_main):
    weak = "minlen=7\nminclass=2\n"
    strong = "minlen=16\nminclass=4\n"
    main = put(tmp_path, "pwquality.conf", weak if weak_main else strong)
    put(tmp_path, "pwquality.conf.d/10.conf", strong if weak_main else weak)
    result = scan(tmp_path, select=["A002"])
    assert not result.errors
    assert bool(result.findings) is weak_main
    if weak_main:
        assert result.findings[0].file == str(main)


@pytest.mark.parametrize("layout", ["single", "multi", "active", "hash"])
def test_rsyslog_comment_lexer(tmp_path, layout):
    action = 'action(type="omfwd" target="example.invalid")'
    text = {
        "single": f"/* {action} */\n",
        "multi": f"/*\n{action}\n*/\n",
        "active": action + "\n",
        "hash": "# " + action + "\n",
    }[layout]
    result = scan(put(tmp_path, "rsyslog.conf", text), select=["R001"])
    assert not result.errors
    assert bool(result.findings) is (layout != "active")


@pytest.mark.parametrize("included", [False, True])
@pytest.mark.parametrize("real_comment", [False, True])
def test_nginx_suppression_requires_comment(tmp_path, included, real_comment):
    marker = "# fstec-lint: ignore N002"
    text = "server {\n" + (marker if real_comment else f'set $x "{marker}";')
    text += "\nautoindex on;\n}\n"
    if included:
        origin = put(tmp_path, "parts/site.conf", text)
        put(tmp_path, "nginx.conf", "http { include parts/*.conf; }\n")
    else:
        origin = put(tmp_path, "nginx.conf", text)
    result = scan(tmp_path, select=["N002"])
    assert not result.errors
    assert bool(result.findings) is (not real_comment)
    if not real_comment:
        assert (result.findings[0].file, result.findings[0].line) == (str(origin), 3)


def test_unrelated_conf_not_guessed(tmp_path):
    put(tmp_path, "other/conf.d/site.conf", "autoindex on;\nminlen=7\n")
    result = scan(tmp_path, select=["N002", "A002"])
    assert not result.errors and not result.findings


@pytest.mark.parametrize("instruction", ["NONE", "CMD true"])
def test_disabled_docker_healthcheck_is_missing(tmp_path, instruction):
    # Docker reference: HEALTHCHECK NONE disables health checking.
    path = put(tmp_path, "Dockerfile", f"FROM alpine:3.20\nHEALTHCHECK {instruction}\n")
    result = scan(path, select=["D006"])
    assert not result.errors
    assert bool(result.findings) is (instruction == "NONE")
