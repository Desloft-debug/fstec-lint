"""Malformed files must be explicit failures, not clean scans or repeated rule errors."""

import json

import pytest

from fstec_lint.cli import main
from fstec_lint.engine import scan
from fstec_lint.parsers.compose import parse_compose


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "false",
        "42",
        "secret-value",
        "services: []",
        "services: secret-value",
        "services: {image: docker}",
        "services: {app: null}",
    ],
)
def test_malformed_compose_is_one_file_error(tmp_path, text):
    path = tmp_path / "docker-compose.yml"
    path.write_text(text)
    with pytest.raises(ValueError, match="unsupported Compose shape"):
        parse_compose(path)
    result = scan(tmp_path)
    assert len(result.errors) == 1
    assert result.errors[0].file == str(path)
    assert not result.findings
    assert "secret-value" not in result.errors[0].message
    assert "не удалось разобрать" in result.errors[0].message


def test_malformed_compose_preserves_other_files_and_fails_cli(tmp_path, capsys):
    (tmp_path / "docker-compose.yml").write_text("services: {image: docker}")
    other = tmp_path / "valid"
    other.mkdir()
    (other / "docker-compose.yml").write_text("services:\n  app:\n    privileged: true\n")
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.20\nUSER root\n")
    result = scan(tmp_path)
    assert len(result.errors) == 1
    assert {"C002", "D001"} <= {f.rule.id for f in result.findings}
    assert main([str(tmp_path), "--fail-on", "none", "--format", "json"]) == 3
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert {"C002", "D001"} <= {finding["rule_id"] for finding in output}
    assert "файлов не удалось обработать: 1" in captured.err


@pytest.mark.parametrize("text", ["null", "~", "services: null", "services: ~"])
def test_explicit_null_is_not_empty_compose(tmp_path, text):
    path = tmp_path / "compose.yaml"
    path.write_text(text)
    result = scan(tmp_path)
    assert len(result.errors) == 1
    assert main([str(tmp_path), "--fail-on", "none"]) == 3


@pytest.mark.parametrize(
    "text",
    [
        "services: {app: {privileged: true}}\nservices: null\n",
        "services: {app: {privileged: true}}\nservices: {}\n",
        "services: {app: {privileged: true, privileged: false}}\n",
        "services: {app: {environment: {1: first, 01: second}}}\n",
        "x-base: &base {privileged: true, privileged: false}\nservices: {app: {<<: *base}}\n",
    ],
)
def test_duplicate_explicit_keys_fail_closed(tmp_path, text):
    path = tmp_path / "compose.yaml"
    path.write_text(text)
    result = scan(tmp_path)
    assert len(result.errors) == 1
    assert main([str(tmp_path), "--fail-on", "none"]) == 3


def test_yaml_merge_explicit_override_remains_supported(tmp_path):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "x-base: &base {privileged: true, user: root}\n"
        "services:\n  app:\n    <<: *base\n    privileged: false\n    user: '1000'\n"
    )
    result = scan(tmp_path, select=["C001", "C002"])
    assert not result.errors
    assert not result.findings


def test_invalid_image_shape_is_one_error_not_seventeen(tmp_path):
    path = tmp_path / "compose.yaml"
    path.write_text("services: {app: {image: [secret-value]}}")
    result = scan(tmp_path)
    assert len(result.errors) == 1
    assert "не удалось разобрать" in result.errors[0].message
    assert "secret-value" not in result.errors[0].message
    assert main([str(tmp_path), "--fail-on", "none"]) == 3
