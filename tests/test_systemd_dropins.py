from pathlib import Path

import pytest

from fstec_lint.engine import scan


def put(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_local_overrides_in_order_and_with_source(tmp_path):
    base = put(tmp_path / "app.service", "[Service]\nUser=root\nProtectHome=tmpfs\n")
    d = tmp_path / "app.service.d"
    put(d / "90-final.conf", "[Service]\nUser=app\nProtectHome=no\n")
    put(d / "10-base.conf", "[Service]\nUser=root\nProtectHome=tmpfs\nNoNewPrivileges=yes\n")
    put(d / "99-ignore.txt", "[Service]\nUser=root\n")
    put(d / ".99-ignore.conf", "[Service]\nUser=root\n")
    result = scan(base, select=["U001", "U002", "U005"])
    assert not result.errors
    assert [(f.rule.id, f.file, f.line) for f in result.findings] == [
        ("U005", str(d / "90-final.conf"), 3)
    ]


def test_fragment_suppression_is_local_to_fragment(tmp_path):
    base = put(tmp_path / "app.service", "[Service]\nUser=app\n")
    put(
        tmp_path / "app.service.d" / "local.conf",
        "[Service]\n# fstec-lint: ignore U001\nUser=root\n",
    )
    result = scan(base, select=["U001"])
    assert not result.findings and not result.errors
    assert result.suppressed == 1


@pytest.mark.parametrize("drop_dir", ["service.d", "web-.service.d", "web-api@.service.d"])
def test_visible_broader_scopes_are_read(tmp_path, drop_dir):
    base = put(tmp_path / "web-api@worker.service", "[Service]\nUser=app\n")
    fragment = put(tmp_path / drop_dir / "local.conf", "[Service]\nUser=root\n")
    result = scan(base, select=["U001"], record_coverage=True)
    assert not result.errors
    assert [(f.file, f.line) for f in result.findings] == [(str(fragment), 2)]
    assert result.coverage == {"U001": {"pass": 0, "fail": 1, "unavailable": 0}}


def test_scope_ties_and_global_lexical_order(tmp_path):
    base = put(tmp_path / "web-api-worker.service", "[Service]\nUser=app\n")
    for scope in ("service.d", "web-.service.d", "web-api-.service.d"):
        put(tmp_path / scope / "40-shared.conf", "[Service]\nProtectHome=tmpfs\n")
    high = put(
        tmp_path / "web-api-worker.service.d" / "40-shared.conf",
        "[Service]\nUser=app\nProtectHome=no\n",
    )
    last = put(tmp_path / "service.d" / "99-all.conf", "[Service]\nUser=root\n")
    result = scan(base, select=["U001", "U005"])
    assert not result.errors
    assert {(f.rule.id, f.file, f.line) for f in result.findings} == {
        ("U001", str(last), 2),
        ("U005", str(high), 3),
    }


def test_template_and_prefix_priority_for_same_basename(tmp_path):
    base = put(tmp_path / "web-api@job-name.service", "[Service]\nUser=app\n")
    put(tmp_path / "web-.service.d" / "10-local.conf", "[Service]\nUser=app\n")
    put(tmp_path / "web-@job-name.service.d" / "10-local.conf", "[Service]\nUser=app\n")
    wanted = put(tmp_path / "web-api@.service.d" / "10-local.conf", "[Service]\nUser=root\n")
    result = scan(base, select=["U001"])
    assert not result.errors
    assert [f.file for f in result.findings] == [str(wanted)]
    put(tmp_path / "web-api@job-name.service.d" / "10-local.conf", "[Service]\nUser=app\n")
    result = scan(base, select=["U001"])
    assert not result.errors and not result.findings


def test_symlink_fragment_outside_scan_boundary_is_incomplete(tmp_path):
    root = tmp_path / "scope"
    base = put(root / "app.service", "[Service]\nUser=app\n")
    outside = put(tmp_path / "outside.conf", "[Service]\nUser=root\n")
    frag = root / "service.d" / "local.conf"
    frag.parent.mkdir()
    try:
        frag.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"system cannot create test symlink: {exc.__class__.__name__}")
    result = scan(base, select=["U001"], record_coverage=True)
    assert [err.code for err in result.errors] == ["systemd_dropin_unresolved"]
    assert not result.findings
    assert result.coverage == {"U001": {"pass": 0, "fail": 0, "unavailable": 1}}


def test_bad_dropin_does_not_pass_base(tmp_path):
    base = put(tmp_path / "app.service", "[Service]\nUser=app\n")
    d = tmp_path / "app.service.d"
    put(d / "local.conf", "[Service]\nUser=" + chr(92))
    result = scan(base, select=["U001"])
    assert [err.code for err in result.errors] == ["systemd_dropin_unresolved"]
