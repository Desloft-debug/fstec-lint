"""Уровень зрелости Узи: структура из Методики оценки ФСТЭК от 07.08.2026.

Методика оценки уровня зрелости деятельности в области технической
защиты информации в информационных системах и обеспечения безопасности
значимых объектов критической информационной инфраструктуры Российской
Федерации (утверждена ФСТЭК России 7 августа 2026 г.). Это вторая из
двух методик, которых требует пункт 31 приказа ФСТЭК N 117: первая —
показатель защищённости Кзи (модуль kzi), вторая — уровень зрелости.

Узи здесь не рассчитывается: методика оценивает деятельность
организации, и большая часть видов требований по конфигурации не
проверяется. Подробности в docs/maturity.md.

Данные выписаны по изложениям документа, сверка с текстом ФСТЭК ещё не
проведена. Пороги таблицы 3 не перенесены, так как в изложениях они
расходятся.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .models import Rule

METHODOLOGY = "Методика оценки уровня зрелости ФСТЭК России от 07.08.2026"

# False, пока формулировки не сверены с текстом ФСТЭК.
VERIFIED_AGAINST_PRIMARY_SOURCE = False


@dataclass(frozen=True)
class Direction:
    """Направление деятельности (п. 12 Методики).

    clause_34 — соответствующий подпункт п. 34 приказа N 117,
    activity — код мероприятия из методического документа от 12.04.2026.
    """

    number: int
    title: str
    clause_34: str | None
    activity: str | None


DIRECTIONS: tuple[Direction, ...] = (
    Direction(1, "Организация и управление деятельностью", None, None),
    Direction(2, "Выявление и оценка угроз безопасности информации", "а", "ВУ"),
    Direction(3, "Контроль конфигураций информационных систем", "б", "КК"),
    Direction(4, "Управление уязвимостями", "в", "КУ"),
    Direction(5, "Управление обновлениями", "г", "КО"),
    Direction(6, "Защита информации при обращении с информацией ограниченного доступа", "д", "ОД"),
    Direction(7, "Защита информации при применении конечных устройств", "е", "ЗУ"),
    Direction(8, "Защита информации при применении мобильных устройств", "ж", "МУ"),
    Direction(9, "Защита удалённого доступа", "з", "УД"),
    Direction(10, "Защита беспроводного доступа", "и", "БД"),
    Direction(11, "Защита привилегированного доступа", "к", "ПД"),
    Direction(12, "Мониторинг информационной безопасности", "л", "МБ"),
    Direction(13, "Разработка безопасного программного обеспечения", "м", "БР"),
    Direction(14, "Физическая защита", "н", "ФЗ"),
    Direction(15, "Непрерывность функционирования", "о", "НФ"),
    Direction(16, "Повышение уровня знаний и информированности", "п", "УЗ"),
    Direction(17, "Защита информации при взаимодействии с подрядными организациями", "р", "ЗП"),
    Direction(18, "Защита от компьютерных атак, направленных на отказ в обслуживании", "с", "ОО"),
    Direction(19, "Защита информации при использовании искусственного интеллекта", "т", "ИИ"),
    Direction(20, "Защита информационных систем и содержащейся в них информации", "у", None),
    Direction(21, "Контроль уровня защищённости", "ф", "ПК"),
)


@dataclass(frozen=True)
class RequirementType:
    """Вид требований к уровню зрелости и его весовой коэффициент."""

    number: int
    title: str
    weight: float


REQUIREMENT_TYPES: tuple[RequirementType, ...] = (
    RequirementType(1, "Документирование", 0.15),
    RequirementType(2, "Выполнение", 0.20),
    RequirementType(3, "Инструменты", 0.10),
    RequirementType(4, "Квалификация", 0.10),
    RequirementType(5, "Контроль", 0.15),
    RequirementType(6, "Обучение", 0.10),
    RequirementType(7, "Внешний аудит", 0.10),
    RequirementType(8, "Актуализация", 0.10),
)

# Шкала уровней зрелости (пункт 9 Методики).
LEVELS: dict[int, str] = {
    0: "нулевой (отсутствует)",
    1: "начальный",
    2: "системный",
    3: "контролируемый",
    4: "верифицируемый",
}

# Целевые уровни (п. 11): (класс ГИС, УЗ ПДн, категория КИИ, уровень).
TARGET_LEVELS: tuple[tuple[str, str, str, int], ...] = (
    ("К3", "УЗ-3, УЗ-4", "3 категория", 1),
    ("К2", "УЗ-2", "2 категория", 2),
    ("К1", "УЗ-1", "1 категория", 3),
)

# Направления, где инструмент сам является средством процесса:
# контроль конфигураций (п. 34 б)) и контроль защищённости (п. 34 ф)).
PROCESS_DIRECTIONS: tuple[int, ...] = (3, 21)

# Виды требований, по которым прогон даёт материал (п. 19 Методики):
# «Инструменты» — применение средства, «Контроль» — регулярный прогон в CI.
SUPPORTED_REQUIREMENTS: tuple[str, ...] = ("Инструменты", "Контроль")


def direction(number: int) -> Direction | None:
    """Направление по номеру из пункта 12, None — если такого нет."""
    for item in DIRECTIONS:
        if item.number == number:
            return item
    return None


def direction_for_activity(activity: str) -> Direction | None:
    """Направление, которому соответствует код мероприятия правила."""
    for item in DIRECTIONS:
        if item.activity == activity:
            return item
    return None


def rules_by_direction(rules: Iterable[Rule]) -> dict[int, tuple[str, ...]]:
    """Номер направления -> id правил (по полю activity)."""
    result: dict[int, list[str]] = {}
    for rule in rules:
        found = direction_for_activity(rule.activity)
        if found is not None:
            result.setdefault(found.number, []).append(rule.id)
    return {number: tuple(sorted(ids)) for number, ids in sorted(result.items())}


def max_supported_share() -> float:
    """Суммарный вес SUPPORTED_REQUIREMENTS (верхняя граница вклада)."""
    return round(
        sum(item.weight for item in REQUIREMENT_TYPES if item.title in SUPPORTED_REQUIREMENTS),
        6,
    )
