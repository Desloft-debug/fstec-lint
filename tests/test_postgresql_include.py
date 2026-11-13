from fstec_lint.engine import scan


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_include_dir_order_and_parent_override(tmp_path):
    main = write(tmp_path / "postgresql.conf", "include_dir 'parts'\nssl=on\n")
    write(tmp_path / "parts/10.conf", "ssl=on\n")
    write(tmp_path / "parts/20.conf", "ssl=off\n")
    write(tmp_path / "parts/.hidden.conf", "ssl=off\n")
    assert not scan(main, select=["P005"]).findings
    main.write_text("ssl=on\ninclude_dir 'parts'\n", encoding="utf-8")
    result = scan(main, select=["P005"])
    assert not result.errors and len(result.findings) == 1
    assert result.findings[0].file == str(tmp_path / "parts/20.conf")


def test_include_missing_optional_and_cycle(tmp_path):
    main = write(tmp_path / "postgresql.conf", "include_if_exists 'missing.conf'\nssl=on\n")
    assert not scan(main, select=["P005"]).errors
    main.write_text("include 'missing.conf'\n", encoding="utf-8")
    assert scan(main, select=["P005"]).errors
    main.write_text("include 'child.conf'\n", encoding="utf-8")
    write(tmp_path / "child.conf", "include 'postgresql.conf'\n")
    assert scan(main, select=["P005"]).errors


def test_include_cannot_escape_and_error_hides_value(tmp_path):
    root = tmp_path / "inside"
    main = write(root / "postgresql.conf", "include '../TEST_CANARY_secret.conf'\n")
    write(tmp_path / "TEST_CANARY_secret.conf", "ssl=on\n")
    result = scan(main, select=["P005"])
    assert result.errors and not result.findings
    assert "TEST_CANARY" not in result.errors[0].message
