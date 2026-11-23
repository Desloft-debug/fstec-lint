from __future__ import annotations

import pytest

from fstec_lint.engine import filter_by_uz, load_rules, scan
from fstec_lint.history import compare, record_scan


@pytest.mark.parametrize(
    ("rule", "directive", "found"),
    [
        ("C018", "pid: host", True),
        ("C018", "pid: 'host'", True),
        ("C018", "pid: service:worker", False),
        ("C018", "pid: ${PID:-host}", False),
        ("C019", "ipc: host", True),
        ("C019", "ipc: shareable", False),
        ("C019", "ipc: ${IPC}", False),
        ("C020", "use_api_socket: true", True),
        ("C020", "use_api_socket: 'true'", True),
        ("C020", "use_api_socket: false", False),
        ("C020", "use_api_socket: ${USE_API_SOCKET:-true}", False),
    ],
)
def test_literal_compose_settings(tmp_path, rule, directive, found):
    cfg = tmp_path / "compose.yaml"
    cfg.write_text(f"services:\n  app:\n    image: alpine:3.23\n    {directive}\n")
    result = scan(cfg, select=[rule])
    assert result.errors == []
    assert bool(result.findings) == found
    if found:
        assert result.findings[0].line == 4
        assert result.findings[0].location == "service:app"


def test_new_matches_keep_their_measure_and_do_not_claim_order21():
    rules = {r.id: r for r in load_rules()}
    for code, measure in (("C018", "ЗКО.5"), ("C019", "ЗКО.5"), ("C020", "ЗКО.3")):
        assert rules[code].submeasure == measure
        assert "№137" in rules[code].orders
        assert rules[code] not in filter_by_uz(list(rules.values()), 1)


@pytest.mark.parametrize("unknown", ["${IPC}", "[host]", "service:sidecar"])
def test_unknown_namespace_is_not_fix(tmp_path, unknown):
    cfg = tmp_path / "compose.yaml"
    db = tmp_path / "history.db"
    for revision, option in (("a", "host"), ("b", unknown)):
        cfg.write_text(f"services:\n  app:\n    ipc: {option}\n")
        result = scan(cfg, select=["C019"], record_checks=True)
        assert not result.errors
        record_scan(
            db, cfg, result, project="sample", revision=revision, profile="one", run_key=None
        )
    assert compare(db, 1, 2)[0]["change"] == "unknown"


def test_password_encryption_without_version_reports_no_assumed_md5(tmp_path):
    cfg = tmp_path / "postgresql.conf"
    cfg.write_text("port = 5432\n")
    result = scan(cfg, select=["P006"])
    assert not result.errors
    assert "не задан явно" in result.findings[0].detail
    assert "md5" not in result.findings[0].detail.lower()
    cfg.write_text("password_encryption = 'md5'\n")
    result = scan(cfg, select=["P006"])
    assert "отличный от" in result.findings[0].detail
    cfg.write_text("password_encryption = 'scram-sha-256'\n")
    assert not scan(cfg, select=["P006"]).findings


def test_compose_models_do_not_hide_api_delegation(tmp_path):
    cfg = tmp_path / "compose.yaml"
    cfg.write_text(
        "services:\n  app:\n    use_api_socket: true\n"
        "    models: [my_model]\nmodels:\n  my_model:\n    model: ai/model\n",
        encoding="utf-8",
    )
    result = scan(cfg, select=["C020"])
    assert not result.errors
    assert [finding.line for finding in result.findings] == [3]


@pytest.mark.parametrize("decl", ["[]", "{my_model: []}", "{my_model: {}}"])
def test_malformed_compose_models_incomplete(tmp_path, decl):
    cfg = tmp_path / "compose.yaml"
    cfg.write_text(f"services: {{app: {{}}}}\nmodels: {decl}\n", encoding="utf8")
    result = scan(cfg, select=["C020"], record_checks=True)
    assert result.errors and not result.findings
    assert result.checks and result.checks[0].status == "unavailable"
