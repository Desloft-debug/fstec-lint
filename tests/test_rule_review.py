from pathlib import Path

import pytest

from fstec_lint.engine import scan


def _scan(tmp_path: Path, name: str, text: str, *rules: str):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    result = scan(path, select=rules)
    assert not result.errors
    return result.findings


def test_postgres_auth_severity(tmp_path):
    findings = _scan(
        tmp_path,
        "pg_hba.conf",
        "local app all trust\nlocal app all md5\n",
        "P001",
        "P009",
    )
    assert [(f.rule.id, f.rule.severity.name.lower(), f.line) for f in findings] == [
        ("P001", "critical", 1),
        ("P009", "medium", 2),
    ]


@pytest.mark.parametrize(
    ("address", "method", "expected"),
    [
        ("all", "reject", False),
        ("samehost", "scram-sha-256", False),
        ("samenet", "scram-sha-256", False),
        ("::/0", "scram-sha-256", True),
        ("0.0.0.0 0.0.0.0", "scram-sha-256", True),
    ],
)
def test_postgres_hba_address(tmp_path, address, method, expected):
    findings = _scan(tmp_path, "pg_hba.conf", f"host app all {address} {method}\n", "P002")
    assert bool(findings) is expected


def test_compose_default_network_in_mixed_topology(tmp_path):
    findings = _scan(
        tmp_path,
        "compose.yaml",
        "services:\n"
        "  ordinary: {image: test}\n"
        "  explicit: {image: test, networks: {default: {}}}\n"
        "  segregated: {image: test, networks: [private]}\n"
        "  isolated: {image: test, network_mode: none}\n"
        "networks: {private: {internal: true}}\n",
        "C016",
    )
    assert {f.location for f in findings} == {"service:ordinary", "service:explicit"}


def test_nginx_tls_evaluates_each_server(tmp_path):
    findings = _scan(
        tmp_path,
        "nginx.conf",
        "http {\n"
        "  server { listen 8443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }\n"
        "  server { listen 9443 ssl; }\n"
        "}\n",
        "N001",
    )
    assert [f.line for f in findings] == [3]


def test_nginx_rate_limits_not_borrowed_from_sibling(tmp_path):
    findings = _scan(
        tmp_path,
        "nginx.conf",
        "http {\n"
        "  limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;\n"
        "  server { location / { limit_req zone=one; } }\n"
        "  server { limit_req zone=one; limit_req_dry_run on; }\n"
        "  server { }\n"
        "}\n",
        "N004",
    )
    assert sorted(f.line for f in findings) == [4, 5]


@pytest.mark.parametrize(
    ("options", "rules"),
    [
        ("DynamicUser=yes\nUser=root\n", {"U001"}),
        ("DynamicUser=yes\n", set()),
        ("User=worker\nPrivateTmp=disconnected\n", set()),
    ],
)
def test_systemd_explicit_user_and_tmp(tmp_path, options, rules):
    findings = _scan(tmp_path, "app.service", "[Service]\n" + options, "U001", "U004")
    assert {f.rule.id for f in findings} == rules


def test_mount_target_does_not_identify_host_socket(tmp_path):
    findings = _scan(
        tmp_path,
        "compose.yaml",
        "services: {app: {volumes: [config:/run/docker.sock]}}\nvolumes: {config: {}}\n",
        "C008",
    )
    assert not findings


@pytest.mark.parametrize(
    ("instruction", "expected"),
    [
        ('ADD --chown=1000:1000 ["https://assets.invalid/config", "/opt/config"]', True),
        ("ADD --checksum=sha256:" + "1" * 64 + " https://assets.invalid/config /opt/", False),
        ("ADD local.txt /opt/", False),
    ],
)
def test_remote_add_checksum_and_supported_forms(tmp_path, instruction, expected):
    findings = _scan(tmp_path, "Dockerfile", "FROM scratch\n" + instruction + "\n", "D002")
    assert bool(findings) is expected


def test_postgres_18_logging_options(tmp_path):
    findings = _scan(
        tmp_path,
        "postgresql.conf",
        "log_connections = 'receipt, authorization'\nlog_disconnections = yes\n",
        "P004",
    )
    assert not findings
