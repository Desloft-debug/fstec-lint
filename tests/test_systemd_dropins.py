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
def test_visible_broader_scopes_are_incomplete(tmp_path, drop_dir):
    base = put(tmp_path / "web-api@worker.service", "[Service]\nUser=app\n")
    put(tmp_path / drop_dir / "local.conf", "[Service]\nUser=root\n")
    result = scan(base, select=["U001"], record_coverage=True)
    assert not result.findings
    assert [err.code for err in result.errors] == ["systemd_dropin_unresolved"]
    assert result.coverage == {"U001": {"pass": 0, "fail": 0, "unavailable": 1}}


def test_bad_dropin_does_not_pass_base(tmp_path):
    base = put(tmp_path / "app.service", "[Service]\nUser=app\n")
    d = tmp_path / "app.service.d"
    put(d / "local.conf", "[Service]\nUser=" + chr(92))
    result = scan(base, select=["U001"])
    assert [err.code for err in result.errors] == ["systemd_dropin_unresolved"]
