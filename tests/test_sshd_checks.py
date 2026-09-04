from fstec_lint.checks import sshd_checks as sc
from fstec_lint.parsers.sshd import parse_sshd_config


def test_permit_root_login_yes_flagged():
    assert len(sc.check_permit_root_login({"permitrootlogin": "yes"})) == 1


def test_permit_root_login_without_password_flagged():
    assert len(sc.check_permit_root_login({"permitrootlogin": "without-password"})) == 1


def test_permit_root_login_no_ok():
    assert sc.check_permit_root_login({"permitrootlogin": "no"}) == []


def test_password_authentication_yes_flagged():
    assert len(sc.check_password_authentication({"passwordauthentication": "yes"})) == 1


def test_password_authentication_no_ok():
    assert sc.check_password_authentication({"passwordauthentication": "no"}) == []


def test_permit_empty_passwords_yes_flagged():
    assert len(sc.check_permit_empty_passwords({"permitemptypasswords": "yes"})) == 1


def test_permit_empty_passwords_default_ok():
    assert sc.check_permit_empty_passwords({}) == []


def test_weak_protocol_flagged():
    assert len(sc.check_weak_protocol({"protocol": "1"})) == 1


def test_protocol_2_ok():
    assert sc.check_weak_protocol({"protocol": "2"}) == []


def test_x11_forwarding_yes_flagged():
    assert len(sc.check_x11_forwarding({"x11forwarding": "yes"})) == 1


def test_x11_forwarding_default_ok():
    assert sc.check_x11_forwarding({}) == []


def test_max_auth_tries_high_flagged():
    assert len(sc.check_max_auth_tries({"maxauthtries": "10"})) == 1


def test_max_auth_tries_default_flagged():
    # sshd-дефолт MaxAuthTries=6 сам по себе превышает рекомендованный порог
    assert len(sc.check_max_auth_tries({})) == 1


def test_max_auth_tries_low_ok():
    assert sc.check_max_auth_tries({"maxauthtries": "4"}) == []


def _config(tmp_path, text):
    path = tmp_path / "sshd_config"
    path.write_text(text, encoding="utf-8")
    return parse_sshd_config(path)


def test_directive_re_enabled_inside_match_block_is_flagged(tmp_path):
    config = _config(
        tmp_path,
        "PermitRootLogin no\n\nMatch Address 10.0.0.0/8\n    PermitRootLogin yes\n",
    )

    findings = sc.check_permit_root_login(config)

    assert len(findings) == 1
    assert findings[0][0] == "sshd_config: PermitRootLogin (Match Address 10.0.0.0/8)"
    assert findings[0][2] == 4


def test_directive_inherited_by_match_block_is_not_reported_twice(tmp_path):
    config = _config(
        tmp_path,
        "PasswordAuthentication yes\n\nMatch User deploy\n    X11Forwarding yes\n",
    )

    # глобальная находка одна, за блок Match её дублировать нельзя:
    # там директива не задана, а унаследована
    assert len(sc.check_password_authentication(config)) == 1


def test_several_match_blocks_are_all_checked(tmp_path):
    config = _config(
        tmp_path,
        "X11Forwarding no\n"
        "\n"
        "Match User deploy\n"
        "    X11Forwarding yes\n"
        "\n"
        "Match Address 192.168.0.0/16\n"
        "    X11Forwarding yes\n",
    )

    scopes = [location for location, _detail, _line in sc.check_x11_forwarding(config)]

    assert scopes == [
        "sshd_config: X11Forwarding (Match User deploy)",
        "sshd_config: X11Forwarding (Match Address 192.168.0.0/16)",
    ]


def test_global_defaults_still_apply_without_match_blocks(tmp_path):
    config = _config(tmp_path, "Port 22\n")

    # PasswordAuthentication по умолчанию yes: отсутствие директивы это не безопасность
    assert len(sc.check_password_authentication(config)) == 1
