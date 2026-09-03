from pathlib import Path

from fstec_lint.parsers.compose import parse_compose
from fstec_lint.parsers.dockerfile import parse_dockerfile
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


def test_parse_dockerfile_vulnerable():
    instructions = parse_dockerfile(EXAMPLES / "vulnerable-stack" / "Dockerfile")
    by_instruction = [i["instruction"] for i in instructions]
    assert by_instruction[0] == "FROM"
    assert "ARG" in by_instruction
    assert "USER" not in by_instruction


def test_parse_dockerfile_handles_line_continuation():
    instructions = parse_dockerfile(EXAMPLES / "hardened-stack" / "Dockerfile")
    run_instructions = [i for i in instructions if i["instruction"] == "RUN"]
    assert any("apt-get update" in i["args"] and "rm -rf" in i["args"] for i in run_instructions)


def test_parsers_record_line_numbers():
    vulnerable = EXAMPLES / "vulnerable-stack"

    compose = parse_compose(vulnerable / "docker-compose.yml")
    assert compose.service_line("db") == 4
    assert compose.service_line("web") == 16
    assert compose.service_line("нет-такого") is None

    sshd = parse_sshd_config(vulnerable / "sshd_config")
    assert sshd.line("permitrootlogin") == 2

    settings = parse_postgresql_conf(vulnerable / "postgresql.conf")
    assert settings.line("listen_addresses") == 1

    hba = parse_pg_hba(vulnerable / "pg_hba.conf")
    assert [record["line"] for record in hba] == [2, 3]

    unit = parse_systemd_unit(vulnerable / "app.service")
    assert unit["Service"].line("ExecStart") == 6


def test_postgresql_conf_keeps_hash_inside_quotes(tmp_path):
    conf = tmp_path / "postgresql.conf"
    conf.write_text("log_line_prefix = '%m [%p] # '  # комментарий\n", encoding="utf-8")

    assert parse_postgresql_conf(conf)["log_line_prefix"] == "%m [%p] # "


def test_parse_compose_of_empty_file_is_empty(tmp_path):
    empty = tmp_path / "docker-compose.yml"
    empty.write_text("", encoding="utf-8")

    assert parse_compose(empty) == {}
