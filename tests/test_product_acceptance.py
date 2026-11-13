"""Product acceptance requirements.

Syntax oracles: PostgreSQL18 auth-pg-hba-conf.html/config-setting.html;
systemd.syntax: comment blocks are ignored within backslash continuations.
Baseline compatibility and atomic containment are explicit user requirements,
A documented limitation cannot weaken those tests.
"""

import json
from pathlib import Path

import pytest
from integration_helpers import cli, write

from fstec_lint import baseline, pdn
from fstec_lint.engine import filter_by_uz, load_rules, scan
from fstec_lint.parsers.base import BoundedReader

SECRET = "TEST_SYNTHETIC_SECRET_b83f7"


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        "include: [base.yaml]\nservices: {}\n",
        "include: [{path: ../outside.yaml}]\nservices: {}\n",
        "services: {app: {extends: {file: base.yaml, service: base}}}\n",
        "services: {base: {privileged: true}, app: {extends: base}}\n",
    ],
)
def test_unresolved_compose_never_reports_complete_clean(tmp_path, capsys, directory, body):
    path = write(tmp_path / "compose.yaml", body)
    write(tmp_path / "base.yaml", "services: {base: {privileged: true}}\n")
    code = cli([str(tmp_path if directory else path), "--select", "C002", "--fail-on", "none"])
    output = capsys.readouterr()
    assert code == 3
    assert output.err.strip() and "Traceback" not in output.err


def test_compose_extension_data_is_not_unresolved_composition(tmp_path):
    path = write(
        tmp_path / "compose.yaml",
        "x-data: {include: benign, extends: benign}\nservices: {app: {privileged: false}}\n",
    )
    result = scan(path, select=["C002"])
    assert not result.findings and not result.errors


@pytest.mark.parametrize(
    ("body", "rule", "count"),
    [
        ('host "app db" all 127.0.0.1/32 trust\n', "P001", 1),
        ('host "app db" "some user" 127.0.0.1/32 md5\n', "P001", 1),
        ('host "db#part" all 127.0.0.1/32 trust # comment\n', "P001", 1),
        ('local "app db" "some user" trust\n', "P001", 1),
        ('host "app db" all 127.0.0.1/32 scram-sha-256\n', "P001", 0),
        ('host "app db" all 0.0.0.0/0 ldap\n', "P002", 1),
        ('host all all "all" trust\n', "P002", 0),
        ("host all all all trust\n", "P002", 1),
        ('host all all "samehost" trust\n', "P002", 0),
        ('host "all" all 0.0.0.0 0.0.0.0 md5\n', "P001", 1),
    ],
)
def test_hba_quoted_fields_keep_rule_meaning_and_origin(tmp_path, body, rule, count):
    path = write(tmp_path / "pg_hba.conf", "# leading comment\n" + body)
    result = scan(path, select=[rule])
    assert not result.errors
    assert len(result.findings) == count
    for finding in result.findings:
        assert (finding.rule.id, finding.file, finding.line) == (rule, str(path), 2)


@pytest.mark.parametrize(
    "body",
    [
        'host "app db all 127.0.0.1/32 trust\n',
        "host all all 127.0.0.1/32 banana\n",
        "host all all 127.0.0.1/32 \\\ntrust\n",
        "# commented continuation \\\nhost all all 127.0.0.1/32 trust\n",
    ],
)
def test_hba_unsupported_lexing_is_private_partial(tmp_path, capsys, body):
    path = write(tmp_path / "pg_hba.conf", body + "# " + SECRET + "\n")
    assert cli([str(path), "--select", "P001", "--fail-on", "none"]) == 3
    output = capsys.readouterr()
    assert output.err.strip()
    assert SECRET not in output.out + output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("separator", ["# comment\n", "; comment\n", "# a\n; b\n\n"])
@pytest.mark.parametrize("user", ["root", "app"])
def test_systemd_comments_do_not_terminate_continuation(tmp_path, separator, user):
    path = write(tmp_path / "app.service", "[Service]\nUser=\\\n" + separator + user + "\n")
    result = scan(path, select=["U001"])
    assert not result.errors
    assert len(result.findings) == (1 if user == "root" else 0)
    if result.findings:
        assert (result.findings[0].file, result.findings[0].line) == (str(path), 2)


def test_systemd_incomplete_continuation_is_partial(tmp_path, capsys):
    path = write(tmp_path / "app.service", "[Service]\nUser=\\\n# " + SECRET + "\n")
    assert cli([str(path), "--select", "U001", "--fail-on", "none"]) == 3
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


@pytest.mark.parametrize(
    "body",
    ["ssl='on\n", "ssl=on\nssl\n", "ssl=on\nssl=\n", 'ssl="on"\n'],
)
def test_checked_postgres_setting_never_invents_safe_value(tmp_path, capsys, body):
    path = write(tmp_path / "postgresql.conf", body + "# " + SECRET + "\n")
    assert cli([str(path), "--select", "P005", "--fail-on", "none"]) == 3
    output = capsys.readouterr()
    assert output.err.strip() and SECRET not in output.out + output.err


@pytest.mark.parametrize("body", ["ssl='on'\n", "SSL on # trailing comment\n"])
def test_supported_postgres_safe_values_remain_clean(tmp_path, body):
    path = write(tmp_path / "postgresql.conf", body)
    result = scan(path, select=["P005"])
    assert not result.errors and not result.findings


@pytest.mark.parametrize("level", [1, 2, 3, 4])
def test_n004_connection_control_mapping_and_uz_are_coherent(level):
    # Order21 appendix UPD.3 covers information-flow control incl. connections;
    # it is a partial subject indicator, not a claim of full measure compliance.
    rules = load_rules()
    rule = next(rule for rule in rules if rule.id == "N004")
    assert rule.pdn_measure == "УПД.3"
    assert rule.pdn_measure_title == pdn.MEASURES["УПД.3"].title
    assert rule.submeasure == "ЗОО.5"
    assert "N004" in {item.id for item in filter_by_uz(rules, level)}


@pytest.mark.parametrize("rule", ["D002", "D005"])
@pytest.mark.parametrize("edit", ["unchanged", "comment", "replace", "insert"])
def test_docker_baseline_distinguishes_existing_debt_from_new(tmp_path, rule, edit):
    def instruction(host):
        if rule == "D002":
            return f"ADD https://{host}.invalid/a /a\n"
        return f"RUN curl https://{host}.invalid/a | sh\n"

    path = write(tmp_path / "Dockerfile", "FROM alpine:3.20\n" + instruction("one"))
    first = scan(path, select=[rule])
    assert not first.errors and len(first.findings) == 1
    known = baseline.load(write(tmp_path / "baseline.json", baseline.render(first.findings)))
    if edit == "comment":
        write(path, "# line shift\nFROM alpine:3.20\n" + instruction("one"))
    elif edit == "replace":
        write(path, "FROM alpine:3.20\n" + instruction("two"))
    elif edit == "insert":
        write(path, "FROM alpine:3.20\n" + instruction("two") + instruction("one"))
    current = scan(path, select=[rule])
    remaining, suppressed = baseline.apply(current.findings, known)
    assert len(remaining) == (1 if edit in {"replace", "insert"} else 0)
    assert suppressed == (0 if edit == "replace" else 1)
    if remaining:
        assert remaining[0].line == 2, "The new instruction must remain, not the shifted old one"


@pytest.mark.parametrize("kind,rule", [("docker_ADD", "D002"), ("hba_LDAP", "P002")])
def test_legacy_baseline_migrates_known_debt_without_accepting_new(
    tmp_path, monkeypatch, capsys, kind, rule
):
    fixture = Path(__file__).parent / "fixtures/legacy-baselines"
    name = "Dockerfile" if kind == "docker_ADD" else "pg_hba.conf"
    body = (fixture / kind / name).read_text(encoding="utf-8")
    body += (
        "ADD https://new.invalid/b /b\n"
        if kind == "docker_ADD"
        else "host all all ::/0 scram-sha-256\n"
    )
    write(tmp_path / kind / name, body)
    old = tmp_path / "old.json"
    old.write_bytes((fixture / ("old-" + kind + "-baseline.json")).read_bytes())
    monkeypatch.chdir(tmp_path)
    code = cli([kind, "--select", rule, "--baseline", str(old), "--format", "json"])
    output = capsys.readouterr()
    assert code == 1, (
        "Known legacy debt needs targeted migration; blanket recreation is insufficient"
    )
    entries = json.loads(output.out)
    assert len(entries) == 1 and entries[0]["rule_id"] == rule
    assert "SYNTHETIC_REVIEW_CREDENTIAL_6df1" not in output.out + output.err


@pytest.mark.parametrize("parent_swap", [False, True])
@pytest.mark.parametrize("surface", ["reader", "main", "include", "suppression"])
def test_atomic_read_never_consumes_external_bytes(tmp_path, monkeypatch, parent_swap, surface):
    selected = tmp_path / "selected"
    # Explicit PostgreSQL inputs must have the supported postgresql.conf name.
    # A generic .conf is only a supported input when reached through Include.
    target_name = "postgresql.conf" if surface == "main" else "value.conf"
    target = write(selected / "parts" / target_name, "ssl=off\n")
    outside = write(
        tmp_path / "outside" / target_name,
        "ssl=off\n# fstec-lint: ignore P005\n# " + SECRET + "\n",
    )
    main = write(selected / "postgresql.conf", f"include 'parts/{target_name}'\n")
    real_open = Path.open
    calls = 0
    reads = []

    class ObservedFile:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.file, name)

        def read(self, *args):
            data = self.file.read(*args)
            reads.append(len(data))
            return data

    def swapped_open(path, *args, **kwargs):
        nonlocal calls
        if path != target:
            return real_open(path, *args, **kwargs)
        calls += 1
        if calls != (2 if surface == "suppression" else 1):
            return real_open(path, *args, **kwargs)
        replaced = target.parent if parent_swap else target
        backup = replaced.with_name(replaced.name + ".owned-backup")
        replaced.rename(backup)
        replaced.symlink_to(
            outside.parent if parent_swap else outside, target_is_directory=parent_swap
        )
        try:
            file = real_open(path, *args, **kwargs)
        finally:
            replaced.unlink()
            backup.rename(replaced)
        return ObservedFile(file)

    monkeypatch.setattr(Path, "open", swapped_open)
    try:
        if surface == "reader":
            BoundedReader(selected).read(target)
        elif surface == "main":
            scan(target, select=["P005"])
        else:
            scan(main, select=["P005"])
    except (ValueError, OSError):
        pass  # A safe refusal is allowed, provided no external bytes were consumed.
    # The product must exercise the hook, and the control read must not trigger it.
    assert calls >= (2 if surface == "suppression" else 1)
    monkeypatch.setattr(Path, "open", real_open)
    assert target.read_bytes() == b"ssl=off\r\n" or target.read_bytes() == b"ssl=off\n"
    assert not reads, "External bytes were consumed through a transient file/parent substitution"
