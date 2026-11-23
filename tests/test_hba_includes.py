from pathlib import Path

import pytest

from fstec_lint.engine import scan
from fstec_lint.parsers.postgres import parse_pg_hba

TRUST = "local app account trust\n"
STRONG = "local app account scram-sha-256\n"


def put(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_nested_paths_order_and_fingerprints(tmp_path):
    path = put(
        tmp_path / "pg_hba.conf",
        TRUST + 'include_dir "access files"\n' + 'include "access files/10-upper.conf"\n' + TRUST,
    )
    group = tmp_path / "access files"
    upper = put(group / "10-upper.conf", 'include "../shared #1.inc"\n' + TRUST)
    lower = put(group / "20-lower.conf", "\n" + TRUST)
    shared = put(tmp_path / "shared #1.inc", TRUST)
    put(group / ".hidden.conf", TRUST)
    put(group / "90-not-a-conf", TRUST)
    put(group / "directory.conf" / "ignored.conf", TRUST)
    records = parse_pg_hba(path)
    assert len(records) == 7
    assert [getattr(item["line"], "file", str(path)) for item in records] == [
        str(p) for p in [path, shared, upper, lower, shared, upper, path]
    ]
    result = scan(path, select=["P001"])
    assert not result.errors
    assert [(f.file, f.line) for f in result.findings] == [
        (str(upper), 2),
        (str(lower), 2),
        (str(path), 1),
        (str(path), 4),
        (str(shared), 1),
    ]
    root_findings = [f for f in result.findings if f.file == str(path)]
    assert [f.location.rsplit(":", 1)[-1] for f in root_findings] == ["1", "2"]


def test_optional_missing_does_not_mask_mandatory_failure(tmp_path):
    path = put(
        tmp_path / "pg_hba.conf",
        'include_if_exists "absent.conf"\ninclude "missing.conf"\ninclude "present.conf"\n' + TRUST,
    )
    present = put(tmp_path / "present.conf", "host all all all md5\n")
    result = scan(path, select=["P001", "P002", "P009"], record_coverage=True)
    assert {f.rule.id for f in result.findings} == {"P001", "P002", "P009"}
    assert len(result.errors) == 1
    assert "строка 2" in result.errors[0].message
    assert result.errors[0].code == "hba_include_unresolved"
    assert "missing.conf" not in result.errors[0].message
    assert result.coverage == {
        r: {"pass": 0, "fail": 0, "unavailable": 1} for r in ("P001", "P002", "P009")
    }
    assert next(f for f in result.findings if f.rule.id == "P009").file == str(present)


@pytest.mark.parametrize("kind", ["include", "include_if_exists", "include_dir"])
def test_outside_path_is_not_read(tmp_path, kind):
    tree = tmp_path / "scoped"
    put(tmp_path / "outside" / "rule.conf", TRUST)
    target = "../outside" if kind == "include_dir" else "../outside/rule.conf"
    base = put(tree / "pg_hba.conf", f'{kind} "{target}"\n' + STRONG)
    result = scan(base, select=["P001"])
    assert not result.findings
    assert [(e.file, e.code) for e in result.errors] == [(str(base), "hba_include_unresolved")]


def test_cycle_and_invalid_sibling_keep_known_records(tmp_path):
    path = put(tmp_path / "pg_hba.conf", "include_dir frags\n")
    bad = put(tmp_path / "frags" / "10-bad.conf", "invalid HBA content\n" + TRUST)
    link = put(tmp_path / "frags" / "20-loop.conf", 'include "../pg_hba.conf"\n')
    good = put(tmp_path / "frags" / "30-good.conf", TRUST)
    result = scan(path, select=["P001"])
    assert {f.file for f in result.findings} == {str(bad), str(good)}
    assert {e.file for e in result.errors} == {str(bad), str(link)}


def test_symlink_fragment_does_not_hide_regular_sibling(tmp_path):
    path = put(tmp_path / "pg_hba.conf", "include_dir frags\n")
    good = put(tmp_path / "frags" / "z.conf", TRUST)
    try:
        (good.parent / "a.conf").symlink_to(good)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    result = scan(path, select=["P001"])
    assert [(f.file, f.line) for f in result.findings] == [(str(good), 1)]
    assert [e.code for e in result.errors] == ["hba_include_unresolved"]


def test_only_fragment_comments_can_suppress_its_records(tmp_path):
    path = put(tmp_path / "pg_hba.conf", 'include "auth.inc" # fstec-lint: ignore P001\n')
    child = put(
        tmp_path / "auth.inc",
        'local "data # fstec-lint: ignore P001" app trust\n'
        "local other app trust # fstec-lint: ignore P001\n",
    )
    result = scan(path, select=["P001"])
    assert not result.errors
    assert [(f.file, f.line) for f in result.findings] == [(str(child), 1)]
    assert result.suppressed == 1
    assert len(scan(path, select=["P001"], inline_exceptions=False).findings) == 2


def test_hba_include_changes_neither_flat_identity_nor_origin(tmp_path):
    fragment = put(tmp_path / "child.conf", TRUST)
    path = put(tmp_path / "pg_hba.conf", TRUST + "include child.conf\n")
    before = scan(path, select=["P001"])
    a = next(f for f in before.findings if f.file == str(path))
    b = next(f for f in before.findings if f.file == str(fragment))
    put(path, "include child.conf\n" + TRUST)
    after = scan(path, select=["P001"])
    assert {f.file: f.location for f in after.findings} == {a.file: a.location, b.file: b.location}
