"""Паспорт уязвимости по ГОСТ Р 56545-2015.

ГОСТ Р 56545-2015 «Защита информации. Уязвимости информационных систем.
Правила описания уязвимостей» (введён приказом Росстандарта от
19.08.2015 N 1180-ст) задаёт структуру описания уязвимости и форму
паспорта (приложение А). Приказ ФСТЭК N 117 ссылается на этот стандарт.

Формат нужен, чтобы результат прогона прикладывался к материалам оценки
как есть, а не переписывался руками. Пункт 20 и) Методики оценки Кзи
называет исходными данными «результаты работы инструментальных средств
оценки (анализа) защищённости»; паспорт — та форма, в которой их ждут.

Элементы, недоступные статическому анализу (версия ПО, аппаратная
платформа, язык программирования), помечаются отметкой «не
определяется». Прочерк в паспорте лучше правдоподобной догадки.
"""

from __future__ import annotations

from datetime import date

from .. import vulnclass
from ..models import Finding, Severity

NOT_DETERMINED = "не определяется статическим анализом конфигурации"

# ГОСТ Р 56545-2015, п. 5.2.18: степень опасности принимает одно из
# четырёх значений. Шкала инструмента совпадает с ней один в один.
SEVERITY_LABEL = {
    Severity.CRITICAL: "критический уровень опасности",
    Severity.HIGH: "высокий уровень опасности",
    Severity.MEDIUM: "средний уровень опасности",
    Severity.LOW: "низкий уровень опасности",
}

# Класс уязвимости (п. 5.2.6) и место возникновения (п. 5.2.12) —
# по ГОСТ Р 56546, пункты 5.1 и 5.3.
VULNERABILITY_CLASS = vulnclass.CONFIGURATION_CLASS
VULNERABILITY_LOCATION = vulnclass.SYSTEM_SOFTWARE

TARGET_SOFTWARE = {
    "compose": "Docker Compose (файл описания развёртывания)",
    "dockerfile": "Docker (файл сборки образа)",
    "postgresql_conf": "PostgreSQL (основной конфигурационный файл)",
    "pg_hba": "PostgreSQL (файл управления доступом клиентов)",
    "sshd_config": "OpenSSH, серверная часть (sshd)",
    "systemd_unit": "systemd (файл модуля службы)",
}


def _identifier(finding: Finding, index: int, today: date) -> str:
    """Идентификатор уязвимости по п. 5.2.3: код БД, год, порядковый номер."""
    return f"FLINT-{today.year}-{index:04d}"


def _detection_rule(finding: Finding) -> str:
    """Способ (правило) обнаружения по п. 5.2.16.

    Формализованное правило у инструмента есть по построению — это сам
    идентификатор проверки и предикат, который она вычисляет.
    """
    return (
        f"Правило {finding.rule.id} инструмента fstec-lint. "
        f"Предикат: {finding.rule.description} "
        f"Проверяемый объект: {finding.relative_file()}, {finding.location}."
    )


def _service_port(finding: Finding) -> str:
    """Служба (порт) по п. 5.2.8 — только там, где находка про порт."""
    if finding.rule.id in ("C005", "C011"):
        return f"{finding.detail.split()[1] if len(finding.detail.split()) > 1 else ''}/tcp".strip(
            "/"
        )
    return NOT_DETERMINED


def _passport(finding: Finding, index: int, today: date) -> list[str]:
    rule = finding.rule
    where = finding.relative_file()
    if finding.line is not None:
        where = f"{where}:{finding.line}"
    rows = [
        ("Наименование уязвимости", f"{rule.title} ({finding.location})"),
        ("Идентификатор уязвимости", _identifier(finding, index, today)),
        ("Идентификаторы других систем описаний уязвимостей", NOT_DETERMINED),
        ("Краткое описание уязвимости", rule.description),
        ("Класс уязвимости", VULNERABILITY_CLASS),
        (
            "Наименование ПО и его версия",
            f"{TARGET_SOFTWARE.get(rule.target, rule.target)}; версия — {NOT_DETERMINED}",
        ),
        ("Служба (порт), которую(ый) используют для функционирования ПО", _service_port(finding)),
        ("Язык программирования ПО", NOT_DETERMINED),
        ("Тип недостатка", rule.weakness_type),
        (
            "Место возникновения (проявления) уязвимости",
            f"{VULNERABILITY_LOCATION}; {where}",
        ),
        ("Идентификатор типа недостатка", rule.cwe),
        ("Наименование операционной системы и тип аппаратной платформы", NOT_DETERMINED),
        ("Дата выявления уязвимости", today.strftime("%d/%m/%Y")),
        ("Автор, опубликовавший информацию о выявленной уязвимости", "—"),
        ("Способ (правило) обнаружения уязвимости", _detection_rule(finding)),
        ("Критерии опасности уязвимости", NOT_DETERMINED),
        ("Степень опасности уязвимости", SEVERITY_LABEL[rule.severity]),
        ("Возможные меры по устранению уязвимости", rule.remediation),
        (
            "Прочая информация",
            f"Мера защиты: {rule.measure} — {rule.measure_title}. "
            f"Подмера: {rule.submeasure} — {rule.submeasure_title}. "
            f"Мероприятие: {rule.activity}. Факт: {finding.detail}",
        ),
    ]
    width = max(len(name) for name, _ in rows)
    out = [f"Паспорт уязвимости № {index} (ГОСТ Р 56545-2015, приложение А)", ""]
    out += [f"{name.ljust(width)} | {value}" for name, value in rows]
    out.append("")
    return out


def render(findings: list[Finding], today: date | None = None) -> str:
    today = today or date.today()
    if not findings:
        return "fstec-lint: нарушений не найдено, паспорта уязвимостей не составлялись."

    lines = [
        "ПАСПОРТА УЯЗВИМОСТЕЙ",
        "Составлены по ГОСТ Р 56545-2015 «Защита информации. Уязвимости",
        "информационных систем. Правила описания уязвимостей».",
        f"Дата составления: {today.strftime('%d/%m/%Y')}. Всего: {len(findings)}.",
        "",
        "=" * 78,
        "",
    ]
    for index, finding in enumerate(findings, start=1):
        lines += _passport(finding, index, today)
        lines += ["-" * 78, ""]
    return "\n".join(lines).rstrip() + "\n"
