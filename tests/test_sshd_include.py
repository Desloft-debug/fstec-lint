"""Include в sshd_config: порядок, первое значение, Match, адреса находок."""

from pathlib import Path

import pytest

from fstec_lint.engine import scan
from fstec_lint.parsers.sshd import parse_sshd_config


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root / "sshd_config"


def test_drop_in_before_main_value_wins(tmp_path):
    config = _tree(
        tmp_path,
        {
            "sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
            "sshd_config.d/50-cloud.conf": "PermitRootLogin yes\n",
        },
    )

    assert parse_sshd_config(config)["permitrootlogin"] == "yes"


def test_main_value_before_include_wins(tmp_path):
    config = _tree(
        tmp_path,
        {
            "sshd_config": "PermitRootLogin no\nInclude sshd_config.d/*.conf\n",
            "sshd_config.d/50-cloud.conf": "PermitRootLogin yes\n",
        },
    )

    assert parse_sshd_config(config)["permitrootlogin"] == "no"


def test_files_are_read_in_lexical_order(tmp_path):
    config = _tree(
        tmp_path,
        {
            "sshd_config": "Include sshd_config.d/*.conf\n",
            "sshd_config.d/20-b.conf": "MaxAuthTries 10\n",
            "sshd_config.d/10-a.conf": "MaxAuthTries 3\n",
        },
    )

    assert parse_sshd_config(config)["maxauthtries"] == "3"


def test_match_in_included_file_ends_with_that_file(tmp_path):
    config = _tree(
        tmp_path,
        {
            "sshd_config": "Include sshd_config.d/*.conf\nX11Forwarding yes\n",
            "sshd_config.d/10-a.conf": "Match User bob\n  PasswordAuthentication yes\n",
        },
    )

    parsed = parse_sshd_config(config)

    assert parsed["x11forwarding"] == "yes"
    assert parsed.matches[0].settings["passwordauthentication"] == "yes"
    assert "x11forwarding" not in parsed.matches[0].settings


def test_include_inside_match_is_conditional(tmp_path):
    config = _tree(
        tmp_path,
        {
            "sshd_config": "Match User bob\n  Include bob.conf\n",
            "bob.conf": "PermitRootLogin yes\n",
        },
    )

    parsed = parse_sshd_config(config)

    assert "permitrootlogin" not in parsed
    assert parsed.matches[0].settings["permitrootlogin"] == "yes"


def test_foreign_absolute_path_is_not_read(tmp_path):
    config = _tree(tmp_path, {"sshd_config": "Include /usr/share/ssh/*.conf\n"})

    assert parse_sshd_config(config) == {}


def test_include_cycle_is_an_error(tmp_path):
    config = _tree(
        tmp_path,
        {"sshd_config": "Include a.conf\n", "a.conf": "Include a.conf\n"},
    )

    with pytest.raises(ValueError, match="циклический"):
        parse_sshd_config(config)


def test_finding_points_to_included_file_and_line(tmp_path):
    _tree(
        tmp_path,
        {
            "sshd_config": "Include sshd_config.d/*.conf\n",
            "sshd_config.d/50-cloud.conf": "# cloud-init\nPermitRootLogin yes\n",
        },
    )

    finding = next(f for f in scan(tmp_path).findings if f.rule.id == "S001")

    assert finding.file.endswith("50-cloud.conf")
    assert finding.line == 2


def test_suppression_comment_in_included_file(tmp_path):
    _tree(
        tmp_path,
        {
            "sshd_config": "Include sshd_config.d/*.conf\n",
            "sshd_config.d/50-cloud.conf": "PermitRootLogin yes  # fstec-lint: ignore S001\n",
        },
    )

    assert not [f for f in scan(tmp_path).findings if f.rule.id == "S001"]
