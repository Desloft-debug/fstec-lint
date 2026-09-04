"""Привязка к приказу ФСТЭК N 21 и фильтр по уровню защищённости ПДн.

Приказ N 21 действует, поэтому его коды — не история, а второй
нормативный контур наравне с приказом N 117 для ГИС. Базовые наборы мер
по уровням заданы приложением к приказу.
"""

import pytest

from fstec_lint import pdn
from fstec_lint.cli import main
from fstec_lint.engine import filter_by_uz, load_rules


def test_every_rule_cites_an_existing_measure_of_order_21():
    for rule in load_rules():
        assert rule.pdn_measure in pdn.MEASURES, (
            f"{rule.id}: меры '{rule.pdn_measure}' нет в приказе N 21"
        )
        assert rule.pdn_measure_title == pdn.MEASURES[rule.pdn_measure].title, (
            f"{rule.id}: наименование меры разошлось с приказом"
        )


def test_measure_group_is_one_of_the_fifteen():
    for rule in load_rules():
        group = pdn.MEASURES[rule.pdn_measure].group
        assert group in pdn.GROUPS, f"{rule.id}: группы '{group}' нет в пункте 8 приказа"


@pytest.mark.parametrize(
    ("rule_id", "measure"),
    [
        # Случаи, где формулировка приказа описывает предмет правила почти
        # дословно. Раньше на этих местах стояли коды из другой области.
        ("S006", "УПД.6"),  # ограничение неуспешных попыток входа
        ("P005", "ЗИС.3"),  # защита ПДн при передаче по каналам связи
        ("C013", "ОДТ.3"),  # контроль безотказного функционирования
        ("U004", "ОПС.4"),  # управление временными файлами
        ("C011", "ЗСВ.1"),  # аутентификация в виртуальной инфраструктуре
    ],
)
def test_exact_matches_stay_put(rule_id, measure):
    rules = {rule.id: rule for rule in load_rules()}

    assert rules[rule_id].pdn_measure == measure


def test_no_rule_points_at_wireless_or_physical_access():
    """Регрессия: ЗИС.20 — беспроводные соединения, ЗТС.3 — вход в помещения.

    Прежняя привязка ставила ЗИС.20 на публикацию порта СУБД и на
    X11Forwarding, а ЗТС.3 — на юнит systemd, работающий от root. Коды
    существуют, но описывают совсем другой предмет, и такая ошибка не
    видна, пока не откроешь приложение к приказу.
    """
    wrong = {rule.id for rule in load_rules() if rule.pdn_measure in ("ЗИС.20", "ЗТС.3", "ЗНИ.1")}

    assert wrong == set()


def test_base_sets_grow_with_the_level():
    """УЗ1 строже УЗ4: базовый набор шире."""
    counts = [len(filter_by_uz(load_rules(), level)) for level in (4, 3, 2, 1)]

    assert counts == sorted(counts), f"наборы не монотонны: {counts}"
    assert counts[0] < counts[-1] < len(load_rules())


def test_uz_filter_narrows_the_scan(tmp_path, capsys):
    (tmp_path / "app.service").write_text("[Service]\nUser=root\nPrivateTmp=no\n", encoding="utf-8")

    main([str(tmp_path), "--fail-on", "none"])
    everything = capsys.readouterr().out

    main([str(tmp_path), "--fail-on", "none", "--uz", "4"])
    base_set = capsys.readouterr().out

    # U004 (PrivateTmp) привязано к ОПС.4, которой нет ни в одном базовом
    # наборе, поэтому под --uz она отсекается, а U001 остаётся.
    assert "U004" in everything
    assert "U004" not in base_set
    assert "U001" in base_set


def test_measures_outside_base_sets_are_not_an_error():
    """Пустой набор уровней — это адаптация, а не ошибка данных.

    Пункты 9 и 10 приказа: меры, не отмеченные в приложении, применяются
    при адаптации базового набора или как компенсирующие.
    """
    adaptive = [code for code, m in pdn.MEASURES.items() if not m.levels]

    assert set(adaptive) == {"ОПС.4", "ОДТ.1"}
