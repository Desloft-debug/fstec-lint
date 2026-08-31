from fstec_lint.checks import sshd_checks as sc


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
