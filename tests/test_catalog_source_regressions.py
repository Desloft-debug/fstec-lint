"""Independent checks from the cited normative texts, not catalogue lookup.

Order 21, appendix pp. 10/14/15 (PDF pages 9/13/14):
https://www.sli.komi.com/files/info_bezop/prikaz_fstek_pers_dan_is.pdf
Methodology 12.04.2026, section IV, measures named below:
https://sudact.ru/law/metodicheskii-dokument-sostav-i-soderzhanie-meropriiatii-i/

These mappings identify a relevant subject; they do not certify compliance.
Each edge is a separate item so one missing code cannot hide the next one.
"""

import pytest

from fstec_lint import measures, pdn
from fstec_lint.engine import filter_by_uz, load_rules

RULES = {rule.id: rule for rule in load_rules()}


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_each_rule_has_resolvable_order21_metadata(rule_id):
    rule = RULES[rule_id]
    assert rule.pdn_measure in pdn.MEASURES
    measure = pdn.MEASURES[rule.pdn_measure]
    assert (rule.pdn_measure_title, measure.group in pdn.GROUPS) == (measure.title, True)


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_each_rule_has_resolvable_methodology_metadata(rule_id):
    rule = RULES[rule_id]
    assert rule.submeasure in measures.SUBMEASURES
    assert rule.submeasure_title == measures.SUBMEASURES[rule.submeasure]


@pytest.mark.parametrize(
    ("rule_id", "code", "title"),
    [
        ("A003", "УПД.3", "Управление учетными записями"),
        ("M001", "ЗЭП.3", "Защита от вредоносных вложений"),
        ("C017", "РСБ.4", "Требования к сбору, хранению и защите данных о событиях безопасности"),
        ("R001", "РСБ.4", "Требования к сбору, хранению и защите данных о событиях безопасности"),
        ("N001", "ЗВТ.1", "Защита пользовательских данных"),
        ("N002", "ЗВТ.2", "Управление доступом пользователей"),
        (
            "N003",
            "ЗВТ.4",
            "Регистрация событий безопасности в веб-приложениях и реагирование на них",
        ),
        ("N004", "ЗОО.5", "Ограничение нагрузки"),
    ],
)
def test_catalog_methodology_edges_match_source(rule_id, code, title):
    rule = RULES[rule_id]
    assert (rule.submeasure, rule.submeasure_title) == (code, title)
    assert measures.SUBMEASURES.get(code) == title


@pytest.mark.parametrize(
    ("rule_id", "code", "title"),
    [
        (
            "A003",
            "УПД.1",
            "Управление (заведение, активация, блокирование и уничтожение) учётными "
            "записями пользователей, в том числе внешних пользователей",
        ),
        ("M001", "АВЗ.1", "Реализация антивирусной защиты"),
    ],
)
def test_catalog_order21_edges_match_source(rule_id, code, title):
    rule = RULES[rule_id]
    assert (rule.pdn_measure, rule.pdn_measure_title) == (code, title)
    assert pdn.MEASURES[code].title == title
    assert pdn.MEASURES[code].levels == frozenset({1, 2, 3, 4})


@pytest.mark.parametrize("level", [1, 2, 3, 4])
def test_restored_order21_measures_remain_in_every_base_set(level):
    assert {"A003", "M001"} <= {rule.id for rule in filter_by_uz(load_rules(), level)}


def test_request_limiting_is_not_fault_tolerant_hardware():
    """Order 21 ODT.1 is hardware fault tolerance, not request throttling.

    No replacement code is invented: the integrator must establish a defensible
    mapping/representation. The methodology independently supplies ZOO.5.
    """
    assert RULES["N004"].pdn_measure != "ОДТ.1", (
        "N004 checks limit_req/limit_conn; Order 21 ОДТ.1 concerns fault-tolerant "
        "technical equipment."
    )
