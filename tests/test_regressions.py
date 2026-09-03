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
from fstec_lint.parsers.postgres import parse_postgresql_conf
from fstec_lint.parsers.systemd import parse_systemd_unit


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
        ('{"version": 3, "findings": {}}', "должно быть списком"),
        ('{"version": 3, "findings": [{"rule_id": "C001"}]}', "без обязательных полей"),
        ('{"version": 3, "findings": ["C001"]}', "без обязательных полей"),
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


# --- 0.9.0: тихие пропуски и ложные находки ----------------------------


def test_scalar_instead_of_list_is_not_iterated_character_by_character(tmp_path):
    """Строка вместо списка не должна обходиться по буквам.

    'volumes: "/var/run/docker.sock:..."' — невалидный compose, но
    посимвольный обход давал и ложные C015 (символ '/' как «смонтирован
    корень хоста»), и молчаливый пропуск C008: ни одна буква не
    совпадала с 'docker.sock'.
    """
    _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  b:\n"
        "    image: redis:7.2\n"
        '    volumes: "/var/run/docker.sock:/var/run/docker.sock"\n'
        '    cap_add: "SYS_ADMIN"\n'
        '    ports: "5432:5432"\n',
    )

    found = {f.rule.id for f in scan(tmp_path).findings}

    assert {"C003", "C005", "C008"} <= found


def test_scalar_volume_does_not_produce_a_finding_per_character(tmp_path):
    """Каждый '/' в строке давал отдельную находку «смонтирован корень хоста»."""
    _write(
        tmp_path / "docker-compose.yml",
        'services:\n  b:\n    image: redis:7.2\n    volumes: "/etc:/host-etc"\n',
    )

    assert sum(f.rule.id == "C015" for f in scan(tmp_path).findings) == 1


def test_pg_hba_address_with_separate_netmask_keeps_the_real_method(tmp_path):
    """Форма «адрес маска» занимает два поля, метод стоит правее.

    Раньше методом становилась маска, а настоящий 'trust' уезжал в
    options — P001 молчал на записи, разрешающей вход без пароля.
    """
    _write(
        tmp_path / "pg_hba.conf",
        "host    all   all   192.168.0.0   255.255.0.0   trust\n",
    )

    findings = scan(tmp_path).findings

    assert [f.rule.id for f in findings] == ["P001"]
    assert "trust" in findings[0].detail


def test_systemd_semicolon_inside_a_value_is_not_a_comment(tmp_path):
    """systemd считает комментарием только строку, начинающуюся с '#'/';'."""
    path = _write(
        tmp_path / "app.service",
        "[Service]\n"
        'Environment="PATH=/usr/local/bin;/usr/bin"\n'
        "ExecStart=/bin/sh -c 'setup ; run'\n",
    )

    service = parse_systemd_unit(path)["Service"]

    assert service["Environment"] == '"PATH=/usr/local/bin;/usr/bin"'
    assert service["ExecStart"] == "/bin/sh -c 'setup ; run'"


def test_systemd_line_continuation_is_one_directive(tmp_path):
    path = _write(
        tmp_path / "app.service",
        "[Service]\nExecStart=/bin/setup \\\n  --user=app\nUser=app\n",
    )

    service = parse_systemd_unit(path)["Service"]

    assert service["ExecStart"] == "/bin/setup --user=app"
    assert "--user" not in service


@pytest.mark.parametrize("value", ["0", "ROOT", "root:root", "0:0"])
def test_u001_recognises_every_form_of_root(value):
    """C001 и D001 ловили uid 0 и регистр, U001 — нет."""
    findings = systemd_checks.check_runs_as_root({"Service": {"User": value}})

    assert len(findings) == 1


def test_postgresql_conf_single_word_line_invents_nothing(tmp_path):
    """'sslx' одним словом не должно читаться как ssl = x."""
    path = _write(tmp_path / "postgresql.conf", "sslx\nssl = on\n")

    settings = parse_postgresql_conf(path)

    assert dict(settings) == {"ssl": "on"}


def test_suppression_works_on_the_offending_directive_line(tmp_path):
    """Комментарий над нарушающей директивой, а не только над сервисом.

    Находки compose числились на строке объявления сервиса, поэтому
    '# fstec-lint: ignore C005' рядом с 'ports' молча не срабатывал —
    ровно так, как этот случай описан в документации.
    """
    _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  db:\n"
        "    image: postgres:16.4\n"
        "    # fstec-lint: ignore C005\n"
        "    ports:\n"
        '      - "5432:5432"\n',
    )

    assert [f.rule.id for f in scan(tmp_path).findings if f.rule.id == "C005"] == []


def test_suppression_next_to_a_list_item_works(tmp_path):
    """Комментарий пишут не у ключа, а у конкретного порта в списке."""
    _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  db:\n"
        "    image: postgres:16.4\n"
        "    ports:\n"
        '      - "5432:5432"   # fstec-lint: ignore C005\n',
    )

    assert [f.rule.id for f in scan(tmp_path).findings if f.rule.id == "C005"] == []


def test_suppression_inline_after_the_directive_works(tmp_path):
    _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  db:\n"
        "    image: postgres:16.4\n"
        '    ports: ["5432:5432"]  # fstec-lint: ignore C005\n',
    )

    assert [f.rule.id for f in scan(tmp_path).findings if f.rule.id == "C005"] == []


def test_suppression_does_not_leak_to_a_neighbouring_service(tmp_path):
    """Область подавления — директива и сервис, а не весь файл."""
    _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  db:  # fstec-lint: ignore C005\n"
        "    image: postgres:16.4\n"
        "    ports:\n"
        '      - "5432:5432"\n'
        "  cache:\n"
        "    image: redis:7.2\n"
        "    ports:\n"
        '      - "6379:6379"\n',
    )

    hits = [f.location for f in scan(tmp_path).findings if f.rule.id == "C005"]

    assert hits == ["service:cache"]


def test_suppression_on_the_service_header_still_covers_the_whole_service(tmp_path):
    _write(
        tmp_path / "docker-compose.yml",
        "services:\n"
        "  db:  # fstec-lint: ignore C005, C002\n"
        "    image: postgres:16.4\n"
        "    privileged: true\n"
        "    ports:\n"
        '      - "5432:5432"\n',
    )

    found = {f.rule.id for f in scan(tmp_path).findings}

    assert "C005" not in found and "C002" not in found


def test_findings_win_over_unreadable_files_in_the_exit_code(tmp_path, capsys):
    """Код 3 не должен прятать нарушение.

    Прогон с одним нечитаемым файлом и critical-находкой возвращал 3, и
    гейт, различающий «нарушения» и «инструмент отработал не полностью»,
    читал его как чистый.
    """
    _write(tmp_path / "Dockerfile", "FROM alpine:3.20\nRUN curl https://x | sh\nUSER app\n")
    (tmp_path / "broken.service").write_bytes(b"\x00\xff\xfe")

    code = main([str(tmp_path), "--fail-on", "critical"])

    assert code == 1
    assert "не удалось обработать: 1" in capsys.readouterr().err


def test_unwritable_output_is_a_usage_error(tmp_path, capsys):
    """Ошибка записи отчёта давала трейсбек и код 1 — как «есть нарушения»."""
    _write(tmp_path / "Dockerfile", "FROM alpine:3.20\n")

    code = main([str(tmp_path), "--fail-on", "none", "-o", str(tmp_path / "нет" / "r.txt")])

    assert code == 2
    assert "не удалось записать" in capsys.readouterr().err


def test_a_crashing_check_does_not_discard_findings_of_other_rules(tmp_path, monkeypatch):
    """Падение одной проверки уносило весь файл и звалось ошибкой разбора."""

    def boom(_compose):
        raise RuntimeError("сломалось")

    monkeypatch.setitem(compose_checks.REGISTRY, "C002", boom)
    _write(tmp_path / "docker-compose.yml", "services:\n  db:\n    image: postgres:latest\n")

    result = scan(tmp_path)

    assert {f.rule.id for f in result.findings}  # находки других правил уцелели
    assert len(result.errors) == 1
    assert "сбой проверки C002" in result.errors[0].message


def test_compose_v1_is_reported_instead_of_passing_silently(tmp_path):
    """Файл без секции services разбирался как пустой — «нарушений нет»."""
    _write(tmp_path / "docker-compose.yml", "db:\n  image: postgres:latest\n  privileged: true\n")

    result = scan(tmp_path)

    assert result.findings == []
    assert len(result.errors) == 1
    assert "docker-compose v1" in result.errors[0].message


@pytest.mark.parametrize("value", ["$$ecretPa55", "$ecret Pa55", "$1234pass"])
def test_value_starting_with_a_dollar_but_not_a_reference_is_a_secret(value):
    """Не всякое значение с '$' в начале — подстановка.

    '$$' в compose экранирует сам знак, то есть '$$ecretPa55' — это
    литерал '$ecretPa55'. Раньше проверка отбрасывала по одному первому
    символу и такие значения пропускала.
    """
    compose = {"services": {"app": {"environment": {"DB_PASSWORD": value}}}}

    assert len(compose_checks.check_secrets_in_environment(compose)) == 1


@pytest.mark.parametrize("value", ["${DB_PASSWORD}", "$DB_PASSWORD", "${DB_PASSWORD:?required}"])
def test_real_substitution_is_not_reported(value):
    compose = {"services": {"app": {"environment": {"DB_PASSWORD": value}}}}

    assert compose_checks.check_secrets_in_environment(compose) == []


def test_truncated_dockerfile_location_stays_unique(tmp_path):
    """Два разных длинных RUN с общим началом делили один адрес.

    Адрес входит в отпечаток для baseline, поэтому одна запись глушила
    обе находки.
    """
    prefix = "curl -sSL https://example.test/very/long/path/that/repeats"
    _write(
        tmp_path / "Dockerfile",
        f"FROM alpine:3.20\nRUN {prefix}/one.sh | sh\nRUN {prefix}/two.sh | bash\nUSER app\n",
    )

    locations = {f.location for f in scan(tmp_path).findings if f.rule.id == "D005"}

    assert len(locations) == 2


def test_dockerfile_detail_is_a_single_line(tmp_path):
    """Тело heredoc уезжало в detail как есть и рвало текстовый отчёт."""
    _write(
        tmp_path / "Dockerfile",
        "FROM alpine:3.20\nRUN <<EOF\ncurl https://x.test/i.sh | sh\nEOF\nUSER app\n",
    )

    details = [f.detail for f in scan(tmp_path).findings if f.rule.id == "D005"]

    assert details and all("\n" not in detail for detail in details)
