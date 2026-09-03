"""Страховка от рассинхрона: YAML с правилами и функции-проверки живут в
разных файлах, и правило без функции (или наоборот) молча ничего не делает."""

from collections import Counter
from pathlib import Path

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
