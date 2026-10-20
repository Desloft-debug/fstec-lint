"""Разбор, проверки и сквозные гарантии для .env-файлов."""

import json
import zipfile

import pytest

from fstec_lint.cli import main
from fstec_lint.engine import discover_files, scan
from fstec_lint.parsers.dotenv import parse_dotenv


def _env(tmp_path, content, name=".env"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_parser_quotes_comments_export_bom_and_lines(tmp_path):
    path = _env(
        tmp_path,
        '\ufeff# comment\nexport PASSWORD = "with # and =" # tail\n'
        "URL: https://host/#fragment\nBARE_KEY\nEMPTY= # empty\n"
        "PRIVATE_KEY='first\nsecond'\nPASSWORD=another\n",
    )
    data = parse_dotenv(path)
    assert [(e.key, e.value, e.line, e.interpolate) for e in data.entries] == [
        ("PASSWORD", "with # and =", 2, True),
        ("URL", "https://host/#fragment", 3, True),
        ("EMPTY", "", 5, True),
        ("PRIVATE_KEY", "first\nsecond", 6, False),
        ("PASSWORD", "another", 8, True),
    ]
    assert data.comments == ((1, "# comment"), (2, "# tail"), (5, "# empty"))


def test_parser_escaped_quotes_and_dollars(tmp_path):
    data = parse_dotenv(_env(tmp_path, "A='Let\\'s go'\n" + r'B="line\n\t\r\\\"\$VALUE"' + "\n"))
    assert data.entries[0].value == "Let's go"
    assert data.entries[1].value == 'line\n\t\r\\"\\$VALUE'


@pytest.mark.parametrize(
    "content",
    [
        "PASSWORD='hidden",
        'PASSWORD="hidden',
        'PASSWORD="hidden" garbage',
        "not=valid\nbad line hidden",
    ],
)
def test_syntax_errors_never_echo_values(tmp_path, content):
    path = _env(tmp_path, content)
    with pytest.raises(ValueError, match="строка") as error:
        parse_dotenv(path)
    assert "hidden" not in str(error.value)
    result = scan(path, select=["E*"])
    assert len(result.errors) == 1
    assert "hidden" not in result.errors[0].message


@pytest.mark.parametrize(
    "name", [".env", ".env.production", ".env.local", ".env.example", "prod.env"]
)
def test_discovery_and_single_file_scans(tmp_path, name):
    path = _env(tmp_path, "DB_PASSWORD=test-value", name)
    assert discover_files(tmp_path)["dotenv"] == [path]
    for root in (tmp_path, path):
        result = scan(root, select=["E*"])
        assert not result.errors
        assert [(f.rule.id, f.location, f.line) for f in result.findings] == [
            ("E001", "variable:DB_PASSWORD", 1)
        ]


@pytest.mark.parametrize("name", [".envrc", "environment", "env.txt"])
def test_unrelated_files_are_not_discovered(tmp_path, name):
    _env(tmp_path, "DB_PASSWORD=test-value", name)
    assert discover_files(tmp_path)["dotenv"] == []


@pytest.mark.parametrize(
    "assignment",
    [
        "DB_PASSWORD=literal",
        "PASSWORD='${EXTERNAL}'",
        'TOKEN="literal"',
        "API_KEY=${EXTERNAL:-fallback}",
        "SECRET=${EXTERNAL-fallback}",
        "PASSWD=$$escaped",
        r'PRIVATE_KEY="\$EXTERNAL"',
        "PWD=literal",
        "AWS_ACCESS_KEY_ID=literal",
        "DATABASE_URL=postgresql://user:literal@db/app",
        "REDIS_URL=redis://default:literal@cache:6379",
        "REDIS_URL=redis://:literal@cache:6379",
        "SECRET=prefix_${EXTERNAL}",
    ],
)
def test_plaintext_secrets(tmp_path, assignment):
    result = scan(_env(tmp_path, assignment), select=["E001"])
    assert not result.errors
    assert len(result.findings) == 1
    assert "literal" not in result.findings[0].detail


@pytest.mark.parametrize(
    "assignment",
    [
        "PASSWORD=",
        "TOKEN= # comment",
        "API_KEY=$EXTERNAL",
        'SECRET="${EXTERNAL}"',
        "SECRET=${EXTERNAL:-}",
        "SECRET=${EXTERNAL-}",
        "SECRET=${EXTERNAL:?required}",
        "PASSWORD_FILE=/run/secrets/password",
        "TOKEN_FILENAME=/secrets/token",
        "DATABASE_URL=postgresql://user:${EXTERNAL}@db/app",
        "DATABASE_URL=postgresql://db/app",
        "TOKENIZER_PARALLELISM=true",
        "PUBLIC_KEY=public",
        "SECRET",
        "# PASSWORD=literal",
    ],
)
def test_non_secrets_and_external_references(tmp_path, assignment, monkeypatch):
    monkeypatch.setenv("EXTERNAL", "host-secret-must-not-be-read")
    result = scan(_env(tmp_path, assignment), select=["E001"])
    assert not result.errors
    assert result.findings == []


def test_duplicates_do_not_hide_secrets(tmp_path):
    result = scan(_env(tmp_path, "PASSWORD=literal\nPASSWORD=\n"), select=["E001"])
    assert [f.line for f in result.findings] == [1]


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", '"TRUE"'])
def test_debug_truthy_values(tmp_path, value):
    result = scan(_env(tmp_path, f"DJANGO_DEBUG={value}\n"), select=["E002"])
    assert len(result.findings) == 1


def test_debug_false_and_unrelated_names(tmp_path):
    result = scan(_env(tmp_path, "DEBUG=false\nDEBUG_LEVEL=1\nDEBUGGER=true\n"), select=["E002"])
    assert not result.findings


@pytest.mark.parametrize(
    "assignment",
    [
        "NODE_TLS_REJECT_UNAUTHORIZED=0",
        "GIT_SSL_NO_VERIFY=true",
        "GIT_SSL_NO_VERIFY=false",
        "GIT_SSL_NO_VERIFY=0",
        "GIT_SSL_NO_VERIFY=",
        "PGSSLMODE=disable",
    ],
)
def test_known_tls_bypasses(tmp_path, assignment):
    result = scan(_env(tmp_path, assignment), select=["E003"])
    assert len(result.findings) == 1


def test_tls_settings_have_exact_semantics(tmp_path):
    result = scan(
        _env(
            tmp_path,
            "NODE_TLS_REJECT_UNAUTHORIZED=1\nPGSSLMODE=verify-full\n"
            "CUSTOM_TLS=false\ngit_ssl_no_verify=true\n",
        ),
        select=["E003"],
    )
    assert not result.findings


@pytest.mark.parametrize(
    "content",
    [
        "# fstec-lint: ignore E001\nPASSWORD=literal\n",
        "PASSWORD=literal # fstec-lint: ignore E*\n",
        "PRIVATE_KEY='first\nsecond' # fstec-lint: ignore E001\n",
    ],
)
def test_real_comments_can_suppress(tmp_path, content):
    result = scan(_env(tmp_path, content), select=["E001"])
    assert not result.findings
    assert result.suppressed == 1


@pytest.mark.parametrize(
    "content",
    [
        'PASSWORD="literal # fstec-lint: ignore E001"\n',
        "PASSWORD=literal#fstec-lint: ignore E001\n",
        "PRIVATE_KEY='first\n# fstec-lint: ignore E001\nlast'\nPASSWORD=literal\n",
    ],
)
def test_values_cannot_suppress_findings(tmp_path, content):
    result = scan(_env(tmp_path, content), select=["E001"])
    assert result.findings
    assert result.suppressed == 0


def test_exclusion_and_rule_filtering_skip_parsing(tmp_path):
    _env(tmp_path, "PASSWORD='unclosed")
    assert not scan(tmp_path, exclude=[".env"]).errors
    assert not scan(tmp_path, ignore=["E*"]).errors
    assert not scan(tmp_path, select=["C*"]).errors


def test_invalid_file_does_not_hide_other_files(tmp_path):
    _env(tmp_path, "PASSWORD='unclosed")
    _env(tmp_path, "PASSWORD=literal", ".env.production")
    result = scan(tmp_path, select=["E*"])
    assert len(result.errors) == 1
    assert len(result.findings) == 1


@pytest.mark.parametrize("format_name", ["text", "json", "html", "sarif", "passport"])
def test_reports_never_contain_secret_values(tmp_path, capsys, format_name):
    marker = "SENSITIVE_VALUE_DO_NOT_PRINT"
    path = _env(tmp_path, f"PASSWORD={marker}\nDATABASE_URL=postgres://user:{marker}@db/app\n")
    assert main([str(path), "--select", "E*", "--format", format_name]) == 1
    captured = capsys.readouterr()
    assert "E001" in captured.out
    assert marker not in captured.out + captured.err


def test_cli_baseline_and_exit_codes(tmp_path, capsys):
    path = _env(tmp_path, "PASSWORD=literal\n")
    baseline = tmp_path / "baseline.json"
    assert main([str(path), "--write-baseline", str(baseline)]) == 0
    assert "literal" not in baseline.read_text(encoding="utf-8")
    assert main([str(path), "--baseline", str(baseline)]) == 0
    assert main([str(path), "--ignore", "E001"]) == 0
    path.write_text("DEBUG=true\n", encoding="utf-8")
    assert main([str(path)]) == 0
    assert main([str(path), "--fail-on", "medium"]) == 1
    path.write_text("bad line\n", encoding="utf-8")
    assert main([str(path)]) == 3
    capsys.readouterr()


def test_catalog_contains_dotenv_rules(capsys):
    assert main(["--list-rules", "--select", "E*", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 3
    assert {r["id"] for r in payload["rules"]} == {"E001", "E002", "E003"}


def test_docx_does_not_contain_secret_values(tmp_path):
    marker = "SENSITIVE_VALUE_DO_NOT_PRINT"
    path = _env(tmp_path, f"PASSWORD={marker}\n")
    output = tmp_path / "report.docx"
    assert main([str(path), "--format", "docx", "--output", str(output)]) == 1
    with zipfile.ZipFile(output) as archive:
        xml = archive.read("word/document.xml").decode("utf-8")
        assert "E001" in xml
        assert marker not in xml


def test_dotenv_uz_filter(tmp_path):
    path = _env(tmp_path, "PASSWORD=literal\nDEBUG=true\nPGSSLMODE=disable\n")
    assert {f.rule.id for f in scan(path, uz=4).findings} == {"E001", "E003"}
    assert {f.rule.id for f in scan(path, uz=3).findings} == {"E001", "E002", "E003"}


def test_sarif_fingerprint_survives_line_shift(tmp_path, capsys):
    path = _env(tmp_path, "PASSWORD=literal\n")
    main([str(path), "--format", "sarif"])
    first = json.loads(capsys.readouterr().out)["runs"][0]["results"][0]
    path.write_text("# new comment\nPASSWORD=literal\n", encoding="utf-8")
    main([str(path), "--format", "sarif"])
    second = json.loads(capsys.readouterr().out)["runs"][0]["results"][0]
    assert first["partialFingerprints"] == second["partialFingerprints"]
    assert second["locations"][0]["physicalLocation"]["region"]["startLine"] == 2


def test_quoted_multiline_whitespace_is_preserved(tmp_path):
    data = parse_dotenv(_env(tmp_path, "PRIVATE_KEY='first  \n  second'\nNORMAL=value   \n"))
    assert data.entries[0].value == "first  \n  second"
    assert data.entries[1].value == "value"
