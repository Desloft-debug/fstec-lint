"""Baseline identities preserve known debt without accepting unrelated changes."""

import json
from pathlib import Path

import pytest

from fstec_lint import baseline
from fstec_lint.engine import scan


@pytest.mark.parametrize(
    "rule,command",
    [
        ("D002", "ADD https://user:{secret}@example.invalid/a?token={secret} /a"),
        ("D005", "RUN curl -u 'user:{secret}' https://example.invalid/a | sh"),
        (
            "D005",
            'RUN TOKEN={secret} curl -H "Authorization: Bearer {secret}" '
            "https://example.invalid/a | sh",
        ),
    ],
)
def test_docker_credential_rotation_keeps_identity(tmp_path, rule, command):
    path = tmp_path / "Dockerfile"
    path.write_text("FROM alpine:3.20\n" + command.format(secret="first"), encoding="utf-8")
    first = scan(path, select=[rule]).findings
    saved = tmp_path / "baseline.json"
    saved.write_text(baseline.render(first), encoding="utf-8")
    path.write_text("FROM alpine:3.20\n" + command.format(secret="second"), encoding="utf-8")
    current = scan(path, select=[rule]).findings
    assert len(first) == len(current) == 1
    assert baseline.apply(current, baseline.load(saved)) == ([], 1)


@pytest.mark.parametrize(
    "first,second",
    [
        ("ADD https://example.invalid/one /a", "ADD https://example.invalid/two /a"),
        (
            "ADD https://example.invalid/a?version=1 /a",
            "ADD https://example.invalid/a?version=2 /a",
        ),
        (
            'RUN curl -H "Host: one.invalid" https://example.invalid/a | sh',
            'RUN curl -H "Host: two.invalid" https://example.invalid/a | sh',
        ),
    ],
)
def test_changed_source_remains_a_new_finding(tmp_path, first, second):
    path = tmp_path / "Dockerfile"
    path.write_text("FROM alpine:3.20\n" + first, encoding="utf-8")
    known = {f.fingerprint() for f in scan(path, select=["D002", "D005"]).findings}
    path.write_text("FROM alpine:3.20\n" + second, encoding="utf-8")
    current = scan(path, select=["D002", "D005"]).findings
    assert len(current) == 1
    assert baseline.apply(current, known) == (current, 0)


def test_duplicate_instruction_does_not_share_baseline_identity(tmp_path):
    path = tmp_path / "Dockerfile"
    command = "ADD https://example.invalid/a /a\n"
    path.write_text("FROM alpine:3.20\n" + command, encoding="utf-8")
    known = {f.fingerprint() for f in scan(path, select=["D002"]).findings}
    path.write_text("FROM alpine:3.20\n" + command * 2, encoding="utf-8")
    remaining, suppressed = baseline.apply(scan(path, select=["D002"]).findings, known)
    assert len(remaining) == suppressed == 1


@pytest.mark.parametrize("variant", ["unselected", "ambiguous", "changed"])
def test_legacy_migration_refuses_unverified_debt(tmp_path, monkeypatch, variant):
    path = tmp_path / "Dockerfile"
    command = "ADD https://example.invalid/old /a\n"
    path.write_text("FROM alpine:3.20\n" + command, encoding="utf-8")
    saved = tmp_path / "baseline.json"
    saved.write_text(
        json.dumps(
            {
                "version": 3,
                "findings": [
                    {
                        "rule_id": "D002",
                        "file": str(path),
                        "location": "stage 1: ADD https://example.invalid/old /a",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    if variant == "ambiguous":
        path.write_text("FROM alpine:3.20\n" + command * 2, encoding="utf-8")
    findings = scan(path, select=["D002"]).findings
    if variant == "unselected":
        findings = []
        real_open = Path.open

        def prohibit_source_open(self, *args, **kwargs):
            assert self != path, "Baseline must not read an unselected source"
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", prohibit_source_open)
    if variant == "changed":
        # The old baseline now matches the reread, but not the selected finding.
        path.write_text("FROM alpine:3.20\nADD https://example.invalid/new /a\n", encoding="utf-8")
    with pytest.raises(baseline.BaselineError, match="--write-baseline"):
        baseline.load(saved, findings=findings, scan_root=tmp_path)
