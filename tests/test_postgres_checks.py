from fstec_lint.checks import postgres_checks as pc


def test_trust_method_flagged():
    records = [{"raw": "local all all trust", "method": "trust"}]
    findings = pc.check_trust_or_md5_auth(records)
    assert len(findings) == 1


def test_md5_method_flagged():
    records = [{"raw": "host all all 10.0.0.0/24 md5", "method": "md5"}]
    findings = pc.check_trust_or_md5_auth(records)
    assert len(findings) == 1


def test_scram_method_ok():
    records = [{"raw": "host all all 10.0.0.0/24 scram-sha-256", "method": "scram-sha-256"}]
    assert pc.check_trust_or_md5_auth(records) == []


def test_open_address_flagged():
    records = [{"raw": "host all all 0.0.0.0/0 md5", "address": "0.0.0.0/0"}]
    assert len(pc.check_open_hba_address(records)) == 1


def test_restricted_address_ok():
    records = [{"raw": "host all all 10.0.0.0/24 md5", "address": "10.0.0.0/24"}]
    assert pc.check_open_hba_address(records) == []


def test_listen_addresses_star_flagged():
    assert len(pc.check_listen_addresses({"listen_addresses": "*"})) == 1


def test_listen_addresses_localhost_ok():
    assert pc.check_listen_addresses({"listen_addresses": "localhost"}) == []


def test_logging_disabled_flagged():
    findings = pc.check_logging_disabled({"log_connections": "off", "log_disconnections": "off"})
    assert len(findings) == 2


def test_logging_enabled_ok():
    findings = pc.check_logging_disabled({"log_connections": "on", "log_disconnections": "on"})
    assert findings == []


def test_ssl_off_flagged():
    assert len(pc.check_ssl_disabled({"ssl": "off"})) == 1


def test_ssl_on_ok():
    assert pc.check_ssl_disabled({"ssl": "on"}) == []


def test_password_encryption_md5_flagged():
    assert len(pc.check_password_encryption({"password_encryption": "md5"})) == 1


def test_password_encryption_scram_ok():
    assert pc.check_password_encryption({"password_encryption": "scram-sha-256"}) == []
