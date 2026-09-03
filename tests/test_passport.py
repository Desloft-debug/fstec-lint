"""Паспорт уязвимости по ГОСТ Р 56545-2015.

Стандарт делит элементы описания на обязательные для идентификации
(п. 5.1.2), обязательные для работ по анализу (п. 5.1.3) и
необязательные (п. 5.1.4). Отчёт, в котором нет обязательного элемента,
паспортом не является, поэтому состав проверяется тестом.
"""

from datetime import date

from fstec_lint.engine import load_rules, scan
from fstec_lint.reporters import passport

# ГОСТ Р 56545-2015, п. 5.1.2 — для однозначной идентификации.
REQUIRED_FOR_IDENTIFICATION = (
    "Идентификатор уязвимости",
    "Наименование уязвимости",
    "Класс уязвимости",
    "Наименование ПО и его версия",
)

# ГОСТ Р 56545-2015, п. 5.1.3 — для обеспечения работ по анализу.
REQUIRED_FOR_ANALYSIS = (
    "Идентификатор типа недостатка",
    "Тип недостатка",
    "Место возникновения (проявления) уязвимости",
    "Способ (правило) обнаружения уязвимости",
    "Возможные меры по устранению уязвимости",
)


def _report(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  db:\n    image: postgres:latest\n    privileged: true\n",
        encoding="utf-8",
    )
    return passport.render(scan(tmp_path).findings, today=date(2026, 9, 3))


def test_every_required_element_is_present(tmp_path):
    report = _report(tmp_path)

    for element in REQUIRED_FOR_IDENTIFICATION + REQUIRED_FOR_ANALYSIS:
        assert element in report, f"нет обязательного элемента: {element}"


def test_severity_uses_the_four_values_of_the_standard():
    """П. 5.2.18: степень опасности принимает одно из четырёх значений."""
    labels = set(passport.SEVERITY_LABEL.values())

    assert labels == {
        "критический уровень опасности",
        "высокий уровень опасности",
        "средний уровень опасности",
        "низкий уровень опасности",
    }


def test_identifier_follows_the_format_of_clause_5_2_3(tmp_path):
    """Код базы, год и порядковый номер, разделённые знаком '-'."""
    report = _report(tmp_path)

    assert "FLINT-2026-0001" in report


def test_every_rule_has_a_weakness_identifier():
    """Без CWE паспорт не собрать: элемент обязателен по п. 5.1.3."""
    for rule in load_rules():
        assert rule.cwe.startswith("CWE-"), f"{rule.id}: нет идентификатора типа недостатка"
        assert rule.weakness_type, f"{rule.id}: нет наименования типа недостатка"


def test_undetermined_elements_are_marked_not_invented(tmp_path):
    """Версия ПО и платформа статикой не определяются — так и написано."""
    report = _report(tmp_path)

    assert report.count(passport.NOT_DETERMINED) >= 4


def test_empty_result_does_not_produce_passports():
    assert "не составлялись" in passport.render([])
