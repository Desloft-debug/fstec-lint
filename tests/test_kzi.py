"""Проверки структуры Кзи, выписанной из Методики оценки ФСТЭК.

Таблица переносится руками, а ошибка в весе или в значении показателя
тихо исказит любую отчётность, которая на неё сошлётся. Внутренняя
арифметика Методики даёт способ это поймать: при всех реализованных
мерах Кзи обязан дать ровно нормированное значение 1.
"""

from fstec_lint import kzi
from fstec_lint.engine import load_rules


def test_group_weights_sum_to_one():
    assert round(sum(group.weight for group in kzi.GROUPS), 6) == 1.0


def test_each_group_indicators_sum_to_one():
    for group in kzi.GROUPS:
        total = round(sum(item.value for item in group.indicators), 6)
        assert total == 1.0, f"группа {group.number}: сумма частных показателей {total}"


def test_all_measures_implemented_gives_the_normative_value():
    """Формула пункта 34 Методики при всех k(j,i) = максимум даёт Кзи = 1."""
    value = sum(sum(item.value for item in group.indicators) * group.weight for group in kzi.GROUPS)

    assert round(value, 6) == kzi.NORMATIVE_VALUE


def test_indicator_codes_are_unique():
    codes = [item.code for group in kzi.GROUPS for item in group.indicators]

    assert len(codes) == len(set(codes)) == 16


def test_supported_indicators_exist_in_the_table():
    for code in kzi.SUPPORTED_INDICATORS:
        assert kzi.indicator(code) is not None, f"показателя {code} нет в таблице 1"


def test_supported_indicators_reference_real_rules():
    """Правило, на которое ссылается показатель, обязано существовать."""
    known = {rule.id for rule in load_rules()}
    for code, rule_ids in kzi.SUPPORTED_INDICATORS.items():
        missing = [rule_id for rule_id in rule_ids if rule_id not in known]
        assert missing == [], f"{code} ссылается на несуществующие правила: {missing}"
