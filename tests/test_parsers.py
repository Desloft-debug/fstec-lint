from pathlib import Path

from fstec_lint.parsers.compose import parse_compose
from fstec_lint.parsers.postgres import parse_pg_hba, parse_postgresql_conf

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
