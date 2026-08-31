from fstec_lint.checks import systemd_checks as sdc


def test_runs_as_root_when_user_missing():
    assert len(sdc.check_runs_as_root({"Service": {}})) == 1


def test_runs_as_root_when_user_is_root():
    assert len(sdc.check_runs_as_root({"Service": {"User": "root"}})) == 1


def test_runs_as_root_ok_with_dedicated_user():
    assert sdc.check_runs_as_root({"Service": {"User": "appsvc"}}) == []


def test_no_new_privileges_missing_flagged():
    assert len(sdc.check_no_new_privileges({"Service": {}})) == 1


def test_no_new_privileges_true_ok():
    assert sdc.check_no_new_privileges({"Service": {"NoNewPrivileges": "true"}}) == []


def test_protect_system_missing_flagged():
    assert len(sdc.check_protect_system({"Service": {}})) == 1


def test_protect_system_strict_ok():
    assert sdc.check_protect_system({"Service": {"ProtectSystem": "strict"}}) == []


def test_private_tmp_missing_flagged():
    assert len(sdc.check_private_tmp({"Service": {}})) == 1


def test_private_tmp_true_ok():
    assert sdc.check_private_tmp({"Service": {"PrivateTmp": "true"}}) == []


def test_protect_home_missing_flagged():
    assert len(sdc.check_protect_home({"Service": {}})) == 1


def test_protect_home_true_ok():
    assert sdc.check_protect_home({"Service": {"ProtectHome": "true"}}) == []
