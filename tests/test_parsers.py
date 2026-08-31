from pathlib import Path

from fstec_lint.parsers.compose import parse_compose
from fstec_lint.parsers.postgres import parse_pg_hba, parse_postgresql_conf
from fstec_lint.parsers.sshd import parse_sshd_config
from fstec_lint.parsers.systemd import parse_systemd_unit

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_parse_compose_vulnerable():
    data = parse_compose(EXAMPLES / "vulnerable-stack" / "docker-compose.yml")
    assert "db" in data["services"]
    assert data["services"]["web"]["privileged"] is True


def test_parse_postgresql_conf():
    settings = parse_postgresql_conf(EXAMPLES / "vulnerable-stack" / "postgresql.conf")
    assert settings["listen_addresses"] == "*"
    assert settings["ssl"] == "off"


def test_parse_pg_hba():
    records = parse_pg_hba(EXAMPLES / "vulnerable-stack" / "pg_hba.conf")
    assert len(records) == 2
    assert records[0]["type"] == "local"
    assert records[0]["method"] == "trust"
    assert records[1]["address"] == "0.0.0.0/0"


def test_parse_sshd_config():
    settings = parse_sshd_config(EXAMPLES / "vulnerable-stack" / "sshd_config")
    assert settings["permitrootlogin"] == "yes"
    assert settings["maxauthtries"] == "10"


def test_parse_sshd_config_stops_at_match(tmp_path):
    tmp = tmp_path / "sshd_config"
    tmp.write_text(
        "PermitRootLogin no\nMatch User backup\n    PermitRootLogin yes\n",
        encoding="utf-8",
    )
    settings = parse_sshd_config(tmp)
    assert settings["permitrootlogin"] == "no"


def test_parse_systemd_unit():
    unit = parse_systemd_unit(EXAMPLES / "hardened-stack" / "app.service")
    assert unit["Service"]["User"] == "appsvc"
    assert unit["Service"]["NoNewPrivileges"] == "true"
    assert unit["Unit"]["After"] == "network.target"
