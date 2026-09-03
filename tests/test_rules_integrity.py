"""Страховка от рассинхрона: YAML с правилами и функции-проверки живут в
разных файлах, и правило без функции (или наоборот) молча ничего не делает."""

import re
from collections import Counter
from pathlib import Path

from fstec_lint import measures
from fstec_lint.checks import (
    compose_checks,
    dockerfile_checks,
    postgres_checks,
    sshd_checks,
    systemd_checks,
)
from fstec_lint.engine import load_rules

REGISTRY_BY_TARGET = {
    "compose": compose_checks.REGISTRY,
    "dockerfile": dockerfile_checks.REGISTRY,
    "pg_hba": postgres_checks.PG_HBA_REGISTRY,
    "postgresql_conf": postgres_checks.POSTGRESQL_CONF_REGISTRY,
    "sshd_config": sshd_checks.REGISTRY,
    "systemd_unit": systemd_checks.REGISTRY,
}


def test_every_rule_has_a_check_function():
    for rule in load_rules():
        registry = REGISTRY_BY_TARGET.get(rule.target)
        assert registry is not None, f"{rule.id}: неизвестный target '{rule.target}'"
        assert rule.id in registry, (
            f"{rule.id} описан в YAML (target={rule.target}), но функции-проверки нет — "
            "правило никогда не сработает"
        )


def test_every_check_function_has_a_rule():
    rule_ids = {rule.id for rule in load_rules()}
    for target, registry in REGISTRY_BY_TARGET.items():
        for check_id in registry:
            assert check_id in rule_ids, (
                f"{check_id} зарегистрирован в checks ({target}), но не описан в rules/*.yaml"
            )


def test_rule_ids_are_unique():
    ids = [rule.id for rule in load_rules()]
    duplicates = [rule_id for rule_id, count in Counter(ids).items() if count > 1]
    assert duplicates == [], f"дублирующиеся id правил: {duplicates}"


def test_rules_have_required_metadata():
    for rule in load_rules():
        assert rule.title, f"{rule.id}: пустой title"
        assert rule.measure, f"{rule.id}: не указана мера ФСТЭК"
        assert rule.measure_title, f"{rule.id}: не указано название меры"
        assert rule.description, f"{rule.id}: пустое описание"
        assert rule.remediation, f"{rule.id}: нет рекомендации по исправлению"
        assert rule.orders, f"{rule.id}: не указано, к какому приказу относится правило"


def test_every_rule_is_described_in_subjects_table():
    """Таблица «правило → предмет» — вход для переустановки кодов мер.

    Правило, которого в ней нет, при миграции просто потеряется.
    """
    table = (Path(__file__).resolve().parent.parent / "docs" / "rules-subjects.md").read_text(
        encoding="utf-8"
    )
    missing = [rule.id for rule in load_rules() if f"| {rule.id} |" not in table]
    assert missing == [], f"нет строки в docs/rules-subjects.md: {missing}"


# --- Привязка к приказу ФСТЭК N 117 ------------------------------------

_MEASURE_RE = re.compile(r"^п\. (\d+) ([а-яё])\)$")


def test_every_rule_cites_an_existing_clause_of_order_117():
    """`measure` обязан ссылаться на реально существующий подпункт.

    Это машинная проверка того, что раньше было утверждением на веру:
    коды вида ЗСВ.2 брались из приложения к приказу N 17, а после его
    отмены сверить их было не с чем.
    """
    for rule in load_rules():
        match = _MEASURE_RE.match(rule.measure)
        assert match is not None, (
            f"{rule.id}: measure '{rule.measure}' не похож на ссылку вида 'п. 63 д)'"
        )
        clause, letter = match.groups()
        assert measures.clause_title(clause, letter) is not None, (
            f"{rule.id}: в приказе N 117 нет подпункта {rule.measure}"
        )


def test_measure_title_matches_the_wording_of_the_order():
    """Наименование меры не должно расходиться с текстом приказа."""
    for rule in load_rules():
        clause, letter = _MEASURE_RE.match(rule.measure).groups()
        assert rule.measure_title == measures.clause_title(clause, letter), (
            f"{rule.id}: measure_title разошёлся с формулировкой приказа для {rule.measure}"
        )


def test_no_rule_claims_a_code_from_the_repealed_order():
    """Коды вида ЗСВ.2 остаются только в legacy_measure.

    Приказ N 17 утратил силу 01.03.2026; ссылка на его код в поле
    `measure` читалась бы как утверждение о соответствии действующим
    требованиям.
    """
    for rule in load_rules():
        assert not re.search(r"[А-ЯЁ]{2,}\.\d", rule.measure), (
            f"{rule.id}: код утратившего силу приказа N 17 в поле measure"
        )
        assert "117" in rule.orders, f"{rule.id}: orders не ссылается на действующий приказ"


def test_container_rules_are_anchored_to_the_container_measure():
    """Меры контейнерных сред — п. 63 д), это прямое попадание в предмет.

    Проверка нужна, чтобы при правках привязки не размылось главное:
    приказ N 117 впервые выделил защиту контейнерных сред и оркестрации
    отдельной базовой мерой, и правила про сам контейнер должны стоять
    именно на ней.
    """
    anchored = {rule.id for rule in load_rules() if rule.measure == "п. 63 д)"}

    assert {"C002", "C003", "C008", "C009", "C015"} <= anchored
