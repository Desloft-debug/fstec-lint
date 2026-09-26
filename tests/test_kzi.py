"""Структура Кзи, выписанная из Методики оценки ФСТЭК.

Проверка весов: при всех реализованных мерах формула даёт ровно 1.
"""

from fstec_lint import kzi
from fstec_lint.engine import load_rules
from fstec_lint.models import Severity


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


def test_k33_lists_every_critical_rule():
    """k33 — критические уязвимости серверов: все правила уровня critical."""
    critical = {rule.id for rule in load_rules() if rule.severity == Severity.CRITICAL}

    assert set(kzi.SUPPORTED_INDICATORS["k33"]) == critical


def test_supported_share_of_kzi():
    """Верхняя граница вклада показателей с материалом — цифра из docs/kzi.md."""
    weights = {group.number: group.weight for group in kzi.GROUPS}
    share = 0.0
    for code in kzi.SUPPORTED_INDICATORS:
        item = kzi.indicator(code)
        assert item is not None
        share += item.value * weights[item.group]

    assert len(kzi.SUPPORTED_INDICATORS) == 10
    assert round(share, 4) == 0.7375
