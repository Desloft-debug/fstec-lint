"""Общий тип результата проверки и предикаты, разделяемые проверками.

Проверка возвращает (location, detail, line) либо
(location, detail, line, scope_line):

* location  — стабильный адрес находки внутри файла; по нему считается
  отпечаток для baseline, поэтому номера строк в него не входят;
* line      — строка нарушающей директивы для отчётов, None если парсер
  её не знает;
* scope_lines — прочие строки, на которых подавляющий комментарий гасит
  эту находку: заголовок блока (сервис в compose) и остальные строки
  нарушающей директивы. Комментарий '# fstec-lint: ignore' пишут и над
  нарушающей строкой, и на заголовке сервиса, и у конкретного элемента
  списка — работать должны все три места.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

CheckResult = tuple[str, str, "int | None"] | tuple[str, str, "int | None", "tuple[int, ...]"]

# Возвращаемый тип проверки. Sequence, а не list: list инвариантен, и
# проверка, собирающая только трёхэлементные результаты, иначе не
# подходила бы под объединение выше.
CheckResults = Sequence[CheckResult]

# root в любой из форм, которыми его задают в compose, Dockerfile и юните
# systemd: имя, числовой uid, пара uid:gid, в кавычках и в любом регистре.
ROOT_UIDS = frozenset({"root", "0"})


def config_line(settings: object, key: str) -> int | None:
    """Строка, где задан ключ, если конфиг разобран парсером с ConfigMap.

    Проверкам передают и обычный dict (юнит-тесты, частичные данные),
    поэтому наличие номеров строк не обязательно.
    """
    line = getattr(settings, "line", None)
    return line(key) if callable(line) else None


def is_root_user(value: object) -> bool:
    """True, если значение директивы user/USER/User указывает на root.

    Один предикат на C001, D001 и U001: три правила судят об одном и том
    же предмете, и расходиться в том, что считать root, они не должны.
    Принимает 'root', 'ROOT', '0', 'root:root', '0:0', значение в
    кавычках — во всех этих формах процесс работает от root.
    """
    uid = str(value).strip().strip("\"'").split(":", 1)[0].strip().lower()
    return uid in ROOT_UIDS


def as_list(value: object) -> list:
    """Значение YAML-поля, которое по схеме должно быть списком.

    Скаляр (строка или число) возвращается как список из одного
    элемента, а не обходится посимвольно: 'volumes: "/etc:/data"' —
    невалидный compose, но перебор строки по буквам давал и ложные
    находки (символ '/' как «смонтирован корень хоста»), и молчаливые
    пропуски (cap_add и docker.sock не совпадали ни с одной буквой).
    """
    if value is None:
        return []
    # Отображение — это одна запись «длинного» синтаксиса, забытая без
    # дефиса ('ports: {target: 5432}'), а не список ключей.
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        return [value]
    return list(value)
