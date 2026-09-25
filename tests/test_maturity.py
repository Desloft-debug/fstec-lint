"""Структура уровня зрелости Узи, выписанная из Методики ФСТЭК от 07.08.2026.

Как и для Кзи, таблица переносится руками, поэтому её держат в
согласии арифметика самой Методики и связь с уже сверенными перечнями:
направления Методики повторяют мероприятия пункта 34 приказа N 117 и
раздела III методического документа от 12.04.2026, и расхождение между
тремя документами — почти всегда опечатка при переносе.
"""

import re
from pathlib import Path

from fstec_lint import maturity, measures
from fstec_lint.engine import load_rules

DOC = Path(__file__).resolve().parent.parent / "docs" / "maturity.md"


def test_requirement_weights_sum_to_one():
    """Максимум по направлению — 1: иначе пороги таблицы 3 не имели бы смысла."""
    assert round(sum(item.weight for item in maturity.REQUIREMENT_TYPES), 6) == 1.0


def test_eight_requirement_types_numbered_in_order():
    assert [item.number for item in maturity.REQUIREMENT_TYPES] == list(range(1, 9))
    titles = [item.title for item in maturity.REQUIREMENT_TYPES]
    assert len(titles) == len(set(titles))


def test_twenty_one_directions_numbered_in_order():
    assert [item.number for item in maturity.DIRECTIONS] == list(range(1, 22))


def test_directions_cover_clause_34_once_except_gossopka():
    """Каждое мероприятие п. 34, кроме х) (ГосСОПКА), — ровно одно направление."""
    used = [item.clause_34 for item in maturity.DIRECTIONS if item.clause_34 is not None]

    assert len(used) == len(set(used))
    assert set(used) == set(measures.ACTIVITIES_34) - {"х"}


def test_directions_cover_every_methodology_activity_once():
    """Все 19 мероприятий раздела III методдокумента разложены по направлениям."""
    used = [item.activity for item in maturity.DIRECTIONS if item.activity is not None]

    assert len(used) == len(set(used))
    assert set(used) == set(measures.ACTIVITIES)


def test_every_rule_lands_in_a_direction():
    """Правило с мероприятием, которого нет среди направлений, выпало бы из отчётности."""
    for rule in load_rules():
        assert maturity.direction_for_activity(rule.activity) is not None, rule.id


def test_rules_by_direction_accounts_for_every_rule():
    grouped = maturity.rules_by_direction(load_rules())

    assert sum(len(ids) for ids in grouped.values()) == len(load_rules())


def test_levels_scale_is_zero_to_four():
    assert sorted(maturity.LEVELS) == [0, 1, 2, 3, 4]


def test_target_levels_grow_with_class_and_stay_on_the_scale():
    levels = [row[3] for row in maturity.TARGET_LEVELS]

    assert levels == sorted(levels)
    assert all(level in maturity.LEVELS for level in levels)


def test_supported_requirements_exist():
    titles = {item.title for item in maturity.REQUIREMENT_TYPES}
    assert set(maturity.SUPPORTED_REQUIREMENTS) <= titles


def test_process_directions_exist():
    for number in maturity.PROCESS_DIRECTIONS:
        assert maturity.direction(number) is not None


def test_supported_share_is_a_quarter():
    """Инструменты 0,10 + Контроль 0,15: цифра, которую приводит docs/maturity.md."""
    assert maturity.max_supported_share() == 0.25


def test_doc_table_matches_rule_mapping():
    """Колонка «Правила» в docs/maturity.md не расходится с полем activity правил."""
    grouped = maturity.rules_by_direction(load_rules())
    text = DOC.read_text(encoding="utf-8")
    rows = re.findall(r"^\|\s*(\d+)\s*\|[^|]*\|\s*([^|]*?)\s*\|", text, flags=re.MULTILINE)

    assert rows, "в docs/maturity.md не найдена таблица направлений"
    documented = {int(number): cell for number, cell in rows}
    for number in range(1, 22):
        expected = ", ".join(grouped.get(number, ())) or "—"
        assert documented.get(number) == expected, f"направление {number}"
