"""Регрессии по разбору и фильтрации.

Каждый тест здесь закрывает случай, в котором инструмент выдавал не
ошибку, а тихо неверный результат: ложную находку либо потерю настоящей.
Для линтера, которым готовятся к оценке соответствия, это худший вид
поломки — отчёт выглядит нормально и читается как истина.
"""

from pathlib import Path

import pytest

from fstec_lint.baseline import BaselineError, load
from fstec_lint.checks import compose_checks, systemd_checks
from fstec_lint.cli import main
from fstec_lint.engine import inline_suppressions, scan
from fstec_lint.models import Severity
from fstec_lint.parsers.dockerfile import parse_dockerfile


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- Dockerfile: '<<' в теле команды не открывает heredoc ---------------


@pytest.mark.parametrize(
    "command",
    [
        'echo "compare a << b"',
        "bash -c 'grep x <<<\"payload\"'",
    ],
)
def test_shell_shift_and_here_string_do_not_swallow_the_file(tmp_path, command):
    """Неоткрытый heredoc не должен съедать остаток Dockerfile.

    Ограничитель, которого нет в файле, раньше уводил все последующие
    инструкции в аргументы RUN: USER и HEALTHCHECK пропадали из разбора,
    и D001/D006 срабатывали на образе, где они есть.
    """
    path = _write(
        tmp_path / "Dockerfile",
        f"FROM alpine:3.20\nRUN {command}\nUSER appuser\nHEALTHCHECK CMD true\n",
    )

    parsed = [inst["instruction"] for inst in parse_dockerfile(path)]

    assert parsed == ["FROM", "RUN", "USER", "HEALTHCHECK"]


def test_real_heredoc_body_is_still_attached_to_its_instruction(tmp_path):
    path = _write(
        tmp_path / "Dockerfile",
        "FROM alpine:3.20\nRUN <<EOF\ncurl -sSL https://x.example/i.sh | bash\nEOF\nUSER app\n",
    )

    parsed = parse_dockerfile(path)

    assert [inst["instruction"] for inst in parsed] == ["FROM", "RUN", "USER"]
    assert "curl -sSL" in parsed[1]["args"]


def test_curl_pipe_shell_inside_heredoc_is_still_detected(tmp_path):
    _write(
        tmp_path / "Dockerfile",
        "FROM alpine:3.20\nRUN <<EOF\ncurl -sSL https://x.example/i.sh | bash\nEOF\n",
    )

    findings = scan(tmp_path, select=["D005"]).findings

    assert [f.rule.id for f in findings] == ["D005"]


# --- Dockerfile: комментарий внутри переноса строки ---------------------


def test_comment_inside_line_continuation_keeps_the_command_whole(tmp_path):
    """Docker отбрасывает такой комментарий и продолжает инструкцию.

    Парсер вместо этого обрывал RUN на комментарии, а хвост команды
    становился отдельной «инструкцией» — D005 на curl | bash после
    комментария молчал.
    """
    path = _write(
        tmp_path / "Dockerfile",
        "FROM alpine:3.20\n"
        "RUN apk add curl \\\n"
        "    # ставим зависимости\n"
        "    && curl -sSL https://x.example/i.sh | bash\n",
    )

    parsed = parse_dockerfile(path)

    assert [inst["instruction"] for inst in parsed] == ["FROM", "RUN"]
    assert parsed[1]["args"] == "apk add curl && curl -sSL https://x.example/i.sh | bash"


def test_curl_pipe_shell_after_a_comment_line_is_detected(tmp_path):
    _write(
        tmp_path / "Dockerfile",
        "FROM alpine:3.20\n"
        "RUN apk add curl \\\n"
        "    # комментарий\n"
        "    && curl -s https://x | bash\n",
    )

    findings = scan(tmp_path, select=["D005"]).findings

    assert [f.rule.id for f in findings] == ["D005"]


# --- Отключённые правила не должны разбирать свои файлы -----------------


def test_deselected_target_is_not_parsed_at_all(tmp_path):
    """Битый файл типа, все правила которого отключены, не роняет прогон.

    Иначе --select/--ignore не спасали: файл всё равно разбирался,
    попадал в errors и уводил CI в код возврата 3.
    """
    (tmp_path / "Dockerfile").write_bytes(b"\xff\xfe binary")
    _write(tmp_path / "docker-compose.yml", "services:\n  db:\n    image: postgres:16.4\n")

    selected = scan(tmp_path, select=["C001"])
    assert selected.errors == []
    assert [f.rule.id for f in selected.findings] == ["C001"]

    ignored = scan(tmp_path, ignore=["D*"])
    assert ignored.errors == []

    # Без фильтров ошибка никуда не делась — это не «тихий» пропуск.
    assert len(scan(tmp_path).errors) == 1


def test_deselected_target_does_not_force_exit_code_3(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_bytes(b"\xff\xfe binary")
    _write(tmp_path / "docker-compose.yml", "services:\n  db:\n    image: postgres:16.4\n")

    assert main([str(tmp_path), "--select", "C001", "--fail-on", "none"]) == 0
    assert main([str(tmp_path), "--fail-on", "none"]) == 3


# --- Подавление комментарием -------------------------------------------


def test_blanket_ignore_is_not_narrowed_by_a_specific_one(tmp_path):
    """'# fstec-lint: ignore' сверху глушит строку целиком.

    Точечный список на самой строке раньше сужал его до себя: пустое
    множество означает «любое правило», а .update() превращал его в
    перечень.
    """
    path = _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  # fstec-lint: ignore\n"
        "  db:  # fstec-lint: ignore C001\n"
        "    image: postgres:16.4\n",
    )

    assert inline_suppressions(path)[3] == set()

    result = scan(tmp_path, select=["C0*"])
    assert result.findings == []
    assert result.suppressed > 1


def test_specific_ignores_on_the_same_line_still_add_up(tmp_path):
    path = _write(
        tmp_path / "docker-compose.yml",
        "services:\n  db:  # fstec-lint: ignore C001, C009\n    image: postgres:16.4\n",
    )

    assert inline_suppressions(path)[2] == {"C001", "C009"}


# --- Baseline: понятная ошибка вместо трейсбека ------------------------


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("[]", "ожидался объект JSON"),
        ('{"version": 2, "findings": {}}', "должно быть списком"),
        ('{"version": 2, "findings": [{"rule_id": "C001"}]}', "без обязательных полей"),
        ('{"version": 2, "findings": ["C001"]}', "без обязательных полей"),
    ],
)
def test_structurally_broken_baseline_raises_baseline_error(tmp_path, content, expected):
    path = _write(tmp_path / "baseline.json", content)

    with pytest.raises(BaselineError, match=expected):
        load(path)


def test_broken_baseline_exits_with_code_2(tmp_path):
    _write(tmp_path / "docker-compose.yml", "services:\n  db:\n    image: postgres:16.4\n")
    baseline = _write(tmp_path / "baseline.json", "[]")

    assert main([str(tmp_path), "--baseline", str(baseline)]) == 2


# --- systemd: булевы значения и DynamicUser ----------------------------


def test_dynamic_user_is_not_reported_as_root():
    """DynamicUser=yes — systemd выдаёт временный непривилегированный uid."""
    unit = {"Service": {"DynamicUser": "yes", "ExecStart": "/usr/bin/app"}}

    assert systemd_checks.check_runs_as_root(unit) == []


def test_missing_user_without_dynamic_user_is_still_reported():
    assert systemd_checks.check_runs_as_root({"Service": {"ExecStart": "/usr/bin/app"}})
    assert systemd_checks.check_runs_as_root({"Service": {"DynamicUser": "no"}})


@pytest.mark.parametrize("value", ["true", "yes", "on", "1", "TRUE", "Yes"])
def test_systemd_accepts_every_boolean_spelling(value):
    """systemd понимает 1/yes/true/on одинаково, проверка обязана тоже."""
    unit = {"Service": {"NoNewPrivileges": value, "PrivateTmp": value}}

    assert systemd_checks.check_no_new_privileges(unit) == []
    assert systemd_checks.check_private_tmp(unit) == []


@pytest.mark.parametrize("value", ["no", "false", "off", "0", ""])
def test_systemd_still_reports_falsy_values(value):
    unit = {"Service": {"NoNewPrivileges": value, "PrivateTmp": value}}

    assert systemd_checks.check_no_new_privileges(unit)
    assert systemd_checks.check_private_tmp(unit)


def test_protect_home_accepts_tmpfs():
    assert systemd_checks.check_protect_home({"Service": {"ProtectHome": "tmpfs"}}) == []


# --- C004: секрет в значении по умолчанию ------------------------------


def test_secret_hardcoded_as_substitution_default_is_reported():
    """${DB_PASSWORD:-changeme} — дефолт лежит в репозитории открытым текстом."""
    compose = {"services": {"db": {"environment": {"DB_PASSWORD": "${DB_PASSWORD:-changeme}"}}}}

    findings = compose_checks.check_secrets_in_environment(compose)

    assert len(findings) == 1
    assert "по умолчанию" in findings[0][1]


@pytest.mark.parametrize(
    "value",
    ["${DB_PASSWORD}", "$DB_PASSWORD", "${DB_PASSWORD:-}", "${DB_PASSWORD:-   }"],
)
def test_substitution_without_a_default_is_not_a_finding(value):
    compose = {"services": {"db": {"environment": {"DB_PASSWORD": value}}}}

    assert compose_checks.check_secrets_in_environment(compose) == []


# --- Прочее ------------------------------------------------------------


def test_unknown_severity_reports_the_allowed_values():
    with pytest.raises(ValueError, match="critical"):
        Severity.from_str("blocker")


def test_list_rules_warns_when_the_format_is_not_supported(capsys):
    assert main(["--list-rules", "--format", "sarif"]) == 0

    captured = capsys.readouterr()
    assert "не поддерживает формат sarif" in captured.err
    assert "Правил всего" in captured.out
