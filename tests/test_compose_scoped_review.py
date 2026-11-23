"""Offline semantic checks on synthetic Compose data, without a runtime."""

from __future__ import annotations

import pytest

from fstec_lint.checks import compose_checks as checks


def _service(**settings: object) -> dict:
    return {"services": {"sample": settings}}


@pytest.mark.parametrize(
    "port", ["5432", 5432, {"target": 5432}, {"target": 5432, "published": ""}]
)
def test_dynamic_publication_short_and_long_forms_match(port: object) -> None:
    hits = checks.check_exposed_sensitive_ports(_service(ports=[port]))
    assert len(hits) == 1
    assert "5432 публикуется без явного адреса" in hits[0][1]


@pytest.mark.parametrize(
    ("host", "message"),
    [
        ("0.0.0.0", "всех интерфейсах IPv4"),
        ("::", "всех интерфейсах IPv6"),
        ("192.0.2.12", "явно заданном адресе"),
    ],
)
def test_address_scope_wording(host: str, message: str) -> None:
    hits = checks.check_exposed_sensitive_ports(_service(ports=[{"target": 5432, "host_ip": host}]))
    assert len(hits) == 1 and message in hits[0][1]


@pytest.mark.parametrize(
    "port",
    [
        "127.0.0.9:5432:5432",
        "[::1]:5432:5432",
        {"target": 5432, "host_ip": "::ffff:127.0.0.9"},
        {"target": 5432, "host_ip": "127.0.0.1"},
    ],
)
def test_loopback_publication_not_external(port: object) -> None:
    assert not checks.check_exposed_sensitive_ports(_service(ports=[port]))


def test_docker_api_is_not_inferred_from_udp() -> None:
    assert checks.check_docker_api_exposed(_service(ports=[{"target": 2375}]))
    assert not checks.check_docker_api_exposed(
        _service(ports=[{"target": 2375, "protocol": "udp"}, "2376/udp"])
    )


def test_cap_drop_is_not_evidence_that_privileges_were_added() -> None:
    assert not checks.check_dangerous_capabilities(_service(cap_add=["CHOWN"]))
    assert not checks.check_dangerous_capabilities(_service(cap_drop=["NET_RAW"]))
    added = checks.check_dangerous_capabilities(_service(cap_add=["NET_ADMIN"], cap_drop=["ALL"]))
    assert "явно добавлены" in added[0][1] and "cap_drop не содержит" not in added[0][1]


def test_unknown_read_only_is_not_a_definite_finding() -> None:
    compose = {
        "services": {
            "uncertain": {"read_only": "${HARDEN:-true}"},
            "concrete": {"read_only": False},
            "defaulted": {},
        }
    }
    assert checks.unresolved_services(compose, "C009") == ("uncertain",)
    assert {row[0] for row in checks.check_no_read_only(compose)} == {
        "service:concrete",
        "service:defaulted",
    }


@pytest.mark.parametrize(
    ("rule", "settings"),
    [
        ("C001", {"user": "${RUN_UID}:100"}),
        ("C002", {"privileged": "${IS_PRIVILEGED:-false}"}),
        ("C003", {"cap_add": ["${ADDED_CAP}"]}),
        ("C005", {"ports": [{"target": "${APP_PORT}"}]}),
        ("C006", {"image": "example/image:${IMAGE_TAG}"}),
        ("C007", {"network_mode": "${NET_MODE}"}),
        ("C008", {"volumes": ["${HOST_MOUNT}"]}),
        ("C010", {"security_opt": ["no-new-privileges:${NNP}"]}),
        ("C011", {"ports": [{"target": 2375, "protocol": "${PROTO}"}]}),
        ("C012", {"mem_limit": "64m", "cpus": "${CPU_COUNT}"}),
        ("C013", {"healthcheck": {"disable": "${DISABLE_HEALTH}"}}),
        ("C014", {"environment": ["APP_DEBUG"]}),
        ("C015", {"volumes": [{"source": "${SOURCE}", "type": "bind"}]}),
        ("C016", {"networks": ["${NET_NAME}"]}),
        ("C017", {"logging": {"driver": "${LOG_DRIVER}"}}),
        ("C018", {"pid": "${PID_MODE}"}),
        ("C019", {"ipc": "service:peer"}),
        ("C020", {"use_api_socket": "${API_SOCKET}"}),
    ],
)
def test_rule_relevant_interpolation_remains_unresolved(rule: str, settings: dict) -> None:
    assert checks.has_unresolved_history_value(_service(**settings), rule)


@pytest.mark.parametrize(
    ("rule", "settings"),
    [
        ("C002", {"image": "example:${IMAGE_TAG}", "privileged": False}),
        ("C003", {"cap_add": ["CHOWN"], "cap_drop": ["ALL", "${DROP_NAME}"]}),
        ("C004", {"environment": {"API_KEY": "${API_KEY}"}}),
        ("C005", {"ports": [{"target": 5432, "published": "${HOST_PORT}"}]}),
        ("C005", {"ports": [{"target": "${APP_PORT}", "host_ip": "127.0.0.1"}]}),
        ("C008", {"volumes": [{"source": "/tmp/sample", "target": "${DEST}", "type": "bind"}]}),
        ("C008", {"volumes": [{"source": "${NAMED}", "type": "volume"}]}),
        ("C011", {"ports": [{"target": "${APP_PORT}", "protocol": "udp"}]}),
        ("C012", {"mem_limit": "64m", "cpus": 1, "cpu_quota": "${IGNORED_QUOTA}"}),
        ("C013", {"healthcheck": {"test": ["CMD", "true", "$${LITERAL}"]}}),
        ("C014", {"environment": {"APP_NAME": "${APP_NAME}"}}),
        ("C016", {"networks": {"${LITERAL_NAME}": None}}),
    ],
)
def test_unrelated_or_redundant_values_do_not_make_rule_unresolved(
    rule: str, settings: dict
) -> None:
    assert not checks.has_unresolved_history_value(_service(**settings), rule)
