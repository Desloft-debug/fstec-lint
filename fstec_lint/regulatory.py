"""Versioned control references. A scan result is not a compliance assessment."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from . import pdn
from .models import Rule

CATALOGUE_VERSION = 1
CHECKED_ON = "2026-11-22"
ORDER_117 = "https://minjust.consultant.ru/documents/55701"
ORDER_137 = "https://publication.pravo.gov.ru/document/0001202608110006"
METHODOLOGY = (
    "https://www.consultant.ru/document/cons_doc_LAW_531896/"
    "2ed7e9a106bb56406785f42d28cff4bd7313d872/"
)
ORDER_21 = "https://sli.komi.com/files/info_bezop/prikaz_fstek_pers_dan_is.pdf"
_CLAUSE = re.compile(r"п\.\s*(34|63)\s*([а-яё])\)")
_GROUP_LETTERS = {
    "ИАФ": "а",
    "УПД": "б",
    "РСБ": "в",
    "ЗСВ": "г",
    "ЗКО": "д",
    "ЗЭП": "е",
    "ЗВТ": "ж",
    "ЗПИ": "з",
    "ЗКУ": "и",
    "ЗМУ": "к",
    "ЗИВ": "л",
    "ЗБД": "м",
    "АВЗ": "н",
    "СОВ": "о",
    "МСЭ": "п",
    "ЗОО": "р",
    "ЗКС": "с",
}

Strength = Literal["direct_signal", "partial", "related"]


@dataclass(frozen=True)
class Assessment:
    strength: Strength
    pages: str
    limitation: str
    enhancement: int | None = None
    classes: tuple[str, ...] = ()


_NAMESPACE = Assessment(
    "direct_signal",
    "109–110",
    "Явное разделение или объединение видно не для всех пространств имён; "
    "действующая конфигурация контейнерной среды не проверяется.",
    1,
    ("К1", "К2"),
)
_AUTHN_STATIC = Assessment(
    "partial",
    "71–74",
    "Проверяется декларация аутентификации, а не применимость к конкретным пользователям, "
    "реальные способы входа и доказательства выполнения меры.",
)
_CONTAINER_ACCESS = Assessment(
    "partial",
    "108–109",
    "Видна декларация доступа; полномочия, реальные субъекты и модель доступа "
    "в контейнерной среде не устанавливаются.",
    classes=("К1", "К2", "К3"),
)
_CONTAINER_INTEGRITY = Assessment(
    "related",
    "106–107",
    "Параметр сборки или доступа на запись не доказывает регулярный контроль "
    "целостности образов и исполняемых файлов.",
)
_CONTAINER_IDENTITY = Assessment(
    "related",
    "110–111",
    "Не устанавливается аутентификация разработчиков и администраторов контейнерной среды. "
    "ИАФ.3 уместна как смежная проверка, только если значение является аутентификатором.",
)
_CONTAINER_INVENTORY = Assessment(
    "related",
    "111–112",
    "Закрепление ссылки на образ не подтверждает его происхождение, подпись, "
    "инвентаризацию или оркестрацию.",
)
_ISOLATION_BASE = Assessment(
    "partial",
    "109–110",
    "Один параметр изоляции не устанавливает фактический доступ к корню хоста, "
    "устройствам, памяти и вводу-выводу.",
    classes=("К1", "К2", "К3"),
)
_REVIEW: dict[str, Assessment] = {
    **dict.fromkeys(("C007", "C018", "C019"), _NAMESPACE),
    **dict.fromkeys(("C008", "C020"), _CONTAINER_ACCESS),
    **dict.fromkeys(
        ("C001", "D001"),
        Assessment(
            "partial",
            "108–109",
            "Явный пользователь процесса не заменяет модель доступа в контейнерной среде. "
            "Если USER образа неизвестен, привилегии состояния не устанавливаются.",
        ),
    ),
    **dict.fromkeys(("C002", "C003", "C015"), _ISOLATION_BASE),
    **dict.fromkeys(("C009", "D002", "D005"), _CONTAINER_INTEGRITY),
    **dict.fromkeys(("C004", "D003"), _CONTAINER_IDENTITY),
    **dict.fromkeys(("C006", "D004"), _CONTAINER_INVENTORY),
    **dict.fromkeys(("P001", "P006", "P009"), _AUTHN_STATIC),
    "C011": Assessment(
        "related",
        "126–127",
        "Типовой порт сам по себе не идентифицирует Docker API, аутентификацию или TLS.",
    ),
    "C012": Assessment(
        "related",
        "172–173",
        "Лимиты CPU/памяти не устанавливают ограничения соединений, DNS и запросов; "
        "это частичный сигнал изоляции ресурсов ЗКО.5.",
    ),
    "C016": Assessment(
        "related",
        "109–110",
        "Общая сеть Compose сама по себе не доказывает нарушение сегментации "
        "или изоляции пространств имён.",
    ),
    "C017": Assessment(
        "partial",
        "96–97",
        "Пересылка журналов не подтверждает состав событий, сроки и защищённость хранения.",
        1,
    ),
    "R001": Assessment(
        "partial",
        "96–97",
        "Пересылка журналов не подтверждает сроки и защищённость хранения.",
        1,
    ),
    "P008": Assessment(
        "related",
        "172–173",
        "Таймаут SQL-запроса не доказывает защиту от отказа в обслуживании "
        "или использование отказоустойчивых технических средств.",
    ),
    "S006": Assessment(
        "partial",
        "82–84",
        "MaxAuthTries действует в одном соединении; блокировка по субъекту "
        "и учёт попыток за период не проверяются.",
    ),
    "S007": Assessment(
        "partial",
        "71–74",
        "Количество методов SSH не устанавливает независимость факторов. "
        "Нужно знать роли, тип доступа, класс, область Match и настройки PAM.",
    ),
    "N001": Assessment(
        "related",
        "118–119",
        "TLS – часть транспортной защиты; нет проверки защиты данных приложения или СКЗИ.",
    ),
    "N003": Assessment(
        "partial",
        "122–123",
        "Access log не доказывает регистрацию событий приложения и сетевого фильтра.",
    ),
    "N004": Assessment(
        "partial",
        "172–173",
        "Наличие одного ограничения не доказывает охват маршрутов, DNS и мониторинг.",
    ),
    "M001": Assessment(
        "related",
        "114–115",
        "Наличие фильтра не устанавливает сканирование вложений и ссылок на вредоносность.",
    ),
}
_UNREVIEWED = Assessment(
    "related", "", "Справочная привязка; требуется проверка применимости и реализация меры."
)


def catalogue_context() -> dict[str, Any]:
    return {
        "schema_version": CATALOGUE_VERSION,
        "checked_on": CHECKED_ON,
        "applicability": "not_determined",
        "compliance_assessed": False,
        "reference_strength": {
            "direct_signal": "Прямой статический признак только части меры",
            "partial": "Частичное свидетельство, нужны дополнительные данные",
            "related": "Справочная или смежная связь, не доказательство",
        },
        "observation_states": {
            "observed": "Статический признак обнаружен",
            "not_observed": "Признак не найден в обработанной области; мера не подтверждена",
            "indeterminate": "Данных недостаточно или разбор неполон",
            "manual": "Требуются другие свидетельства или ручная проверка",
        },
    }


def _order_reference(
    paragraph: str, letter: str, strength: Strength, relation: str
) -> dict[str, Any]:
    return {
        "document": "order_117",
        "revision": "2026-05-08",
        "effective_from": "2026-03-01",
        "revision_in_force_from": "2026-09-01",
        "revision_exception": {"paragraph": 32, "effective_from": "2027-03-01"},
        "amending_order_url": ORDER_137,
        "url": ORDER_117,
        "clause": {
            "paragraph": int(paragraph),
            "letter": letter,
        },
        "kind": "process" if paragraph == "34" else "base_measure",
        "relation": relation,
        "strength": strength,
    }


def _method_reference(code: str, assessment: Assessment) -> dict[str, Any]:
    return {
        "document": "methodology_2026_04_12",
        "revision": "2026-04-12",
        "url": METHODOLOGY,
        "clause": {"section": "IV", "code": code, "enhancement": assessment.enhancement},
        "printed_pages": assessment.pages or None,
        "class_criteria": list(assessment.classes) or None,
        "strength": assessment.strength,
    }


def metadata(rule: Rule) -> dict[str, Any]:
    """Machine-readable reference context, not an observation or compliance score."""
    audit = _REVIEW.get(rule.id, _UNREVIEWED)
    references: list[dict[str, Any]] = []
    letters = _GROUP_LETTERS.get(rule.submeasure.partition(".")[0])
    if letters:
        references.append(_order_reference("63", letters, audit.strength, "methodology_parent"))
    for paragraph, letter in _CLAUSE.findall(rule.measure):
        if paragraph == "63" and letter == letters:
            continue
        references.append(_order_reference(paragraph, letter, "related", "legacy_catalogue"))
    if rule.submeasure:
        references.append(_method_reference(rule.submeasure, audit))
    if rule.id == "C012":
        references.append(_order_reference("63", "д", "partial", "additional_signal"))
        references.append(_method_reference("ЗКО.5", _ISOLATION_BASE))
    if rule.id == "C017":
        references.append(_method_reference("ЗКО.2", Assessment("related", "108", "")))
    pdn_entry = pdn.measure(rule.pdn_measure)
    if pdn_entry:
        references.append(
            {
                "document": "order_21",
                "revision": "2020-05-14",
                "url": ORDER_21,
                "clause": {"section": "Приложение", "code": pdn_entry.code},
                "baseline_security_levels": sorted(pdn_entry.levels),
                "strength": "related",
            }
        )
    return {
        "assessed_reference": rule.id in _REVIEW,
        "applicability": "not_determined",
        "evidence": "static_configuration",
        "manual_verification_required": True,
        "compliance_assessed": False,
        "limitation": audit.limitation,
        "references": references,
    }
