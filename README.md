# fstec-lint

[![CI](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Статический аудит инфраструктуры (Docker Compose, Dockerfile, PostgreSQL,
sshd_config, юниты systemd) с привязкой каждого из **40 правил** к
конкретной мере защиты информации из регуляторной базы ФСТЭК России для
ПДн и ГИС.

Аналоги вроде Docker Bench, Lynis, Trivy или Checkov отлично находят
проблемы, но мапят их на CIS Benchmarks / NIST. Ответа на вопрос
«какую меру из приказа ФСТЭК закрывает этот фикс» они не дают, а именно
он нужен на этапе подготовки к аттестации ГИС или к оценке соответствия
ИСПДн. `fstec-lint` закрывает этот разрыв: находка → конкретная мера
(ИАФ, УПД, ЗСВ, РСБ, ЗИС, ЗПИ и т.д.) → как исправить.

> **Важно.** Инструмент помогает готовиться к оценке соответствия и
> ускоряет самопроверку перед аттестацией, но не заменяет её и не
> является сертифицированным средством защиты информации. Соответствие
> находок конкретным пунктам приказов носит справочный характер —
> перед использованием в реальном проекте сверьте номера мер с
> действующей редакцией приказа/методического документа и вашей моделью
> угроз. См. раздел «Правовой статус» ниже — база сейчас в процессе
> замены.

## Правовой статус (на 01.09.2026)

Регуляторная база ФСТЭК в 2025–2026 гг. серьёзно обновилась, и правила
проекта явно привязаны к актуальным документам через поле `orders` в
метаданных каждого правила:

- **Приказ №17** (защита ГИС) **утратил силу**. Его заменил
  **приказ ФСТЭК №117** от 11.04.2025 (зарегистрирован Минюстом
  16.06.2025, №82619), действующий **с 1 марта 2026 года**. Состав мер
  расширен до 18 групп, добавлены новые обязательные группы — в том
  числе **ЗПИ** (защита программных интерфейсов приложений/API), ЗКУ
  (защита конечных устройств) и ЗИВ (защита устройств IoT), которых не
  было в старом приказе №17. Правило C011 (незащищённый Docker API)
  явно ссылается на новую группу ЗПИ.
- **Приказ №21** (защита ПДн) формально ещё действует, но 24.07.2026
  ФСТЭК опубликовала проект приказа о его **полной отмене** и переходе
  на модель самостоятельного выбора мер оператором с метрикой УЗИ
  (уровень зрелости защиты информации). Общественное обсуждение
  завершилось 08.08.2026, изначально планируемая дата вступления —
  01.09.2026 — уже наступила, но по состоянию на эту дату приказ
  **всё ещё не зарегистрирован в Минюсте**, то есть дата вступления в
  силу сдвигается.

Практический вывод: коды мер (ИАФ, УПД, ЗСВ и т.д.) в большинстве своём
сохранились между старой и новой базой, поэтому маппинг находок остаётся
осмысленным, но как только новый приказ взамен №21 будет официально
издан — потребуется актуализировать `fstec_lint/rules/*.yaml`. Это
осознанно оставлено первым пунктом Roadmap.

Источники: [CISOClub о новом приказе ФСТЭК взамен №21](https://cisoclub.ru/fstjek-rossii-gotovit-otmenu-prikaza-21-i-novuju-sistemu-zashhity-personalnyh-dannyh/), [обзор приказа №117 (Angara Security)](https://www.angarasecurity.ru/stati/analiz-prikaza-fstek-rossii-117/), [BI.ZONE о группах мер приказа №117](https://bi.zone/expertise/insights/prikaz-fstek-rossii-117-novyy-etap-zashchity-informatsii-v-gossektore/).

---

## Что проверяется

**Docker Compose** (`docker-compose.yml` / `compose.yaml`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| C001 | Контейнер без `user:` — работает от root | УПД.4 / ЗСВ.2 |
| C002 | `privileged: true` | ЗСВ.2 / УПД.4 |
| C003 | Опасные `cap_add` (`SYS_ADMIN`, `NET_ADMIN`, `ALL`...) | ЗСВ.2 |
| C004 | Пароль/токен в открытом виде в `environment` | ЗНИ.1 / ИАФ.1 |
| C005 | Порт СУБД опубликован на все интерфейсы | ЗИС.20 / УПД.4 |
| C006 | Образ без версии или digest (`:latest`) | ОЦЛ.1 / АНЗ.1 |
| C007 | `network_mode: host` | ЗСВ.2 / ЗИС.20 |
| C008 | Смонтирован `docker.sock` | ЗСВ.2 / УПД.4 |
| C009 | Файловая система контейнера не `read_only` | ОЦЛ.1 |
| C010 | Нет `no-new-privileges:true` | ЗСВ.2 |
| C011 | Docker Engine API (порт 2375/2376) опубликован наружу | ЗСВ.2 / ЗПИ.1 |
| C012 | Нет ограничений ресурсов (mem_limit/cpus/deploy.resources.limits) | ОДТ.1 |
| C013 | Нет `healthcheck` | ОДТ.3 |
| C014 | Включён debug-режим (`*DEBUG=true`) | АНЗ.1 / ЗИС.3 |
| C015 | Смонтирован чувствительный путь хоста (`/`, `/etc`, `/proc`...) | ЗСВ.2 |

**PostgreSQL** (`postgresql.conf` / `pg_hba.conf`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| P001 | `trust`/`md5` в `pg_hba.conf` | ИАФ.1 / ИАФ.4 |
| P002 | Подключение разрешено с `0.0.0.0/0` | УПД.4 |
| P003 | `listen_addresses = '*'` | ЗИС.20 |
| P004 | Логирование подключений выключено | РСБ.1 / РСБ.3 |
| P005 | `ssl = off` | ЗИС.17 / ЗНИ.1 |
| P006 | `password_encryption = md5` | ИАФ.1 |
| P007 | `log_statement` не `ddl`/`mod`/`all` | РСБ.2 |
| P008 | Не задан `statement_timeout` | ОДТ.1 |

**SSH** (`sshd_config`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| S001 | `PermitRootLogin yes`/`without-password` | УПД.4 / ИАФ.1 |
| S002 | `PasswordAuthentication yes` | ИАФ.4 |
| S003 | `PermitEmptyPasswords yes` | ИАФ.1 |
| S004 | Включён устаревший `Protocol 1` | ЗИС.17 |
| S005 | `X11Forwarding yes` | ЗИС.20 |
| S006 | `MaxAuthTries` больше 4 | УПД.4 |

**systemd** (`*.service`, секция `[Service]`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| U001 | Сервис выполняется от root (`User` не задан) | УПД.4 / ЗТС.3 |
| U002 | Нет `NoNewPrivileges=true` | ЗСВ.2 |
| U003 | Нет `ProtectSystem=full`/`strict` | ОЦЛ.1 |
| U004 | Нет `PrivateTmp=true` | ЗСВ.2 |
| U005 | Нет `ProtectHome=true` | УПД.4 |

**Dockerfile** (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| D001 | В финальном стейдже нет `USER` | УПД.4 / ЗСВ.2 |
| D002 | `ADD` загружает файл по URL без проверки | ОЦЛ.1 / АНЗ.1 |
| D003 | Секрет передан через `ARG` | ЗНИ.1 / ИАФ.1 |
| D004 | Базовый образ (`FROM`) не закреплён по версии | ОЦЛ.1 / АНЗ.1 |
| D005 | `curl`/`wget` передаётся напрямую в shell (`\| sh`) | ОЦЛ.1 / АНЗ.1 |
| D006 | Не задан `HEALTHCHECK` | ОДТ.3 |

Полное описание, факт и рекомендация по каждому правилу — в
[`fstec_lint/rules/`](fstec_lint/rules/). Правила описаны декларативно в
YAML: чтобы добавить новую меру или изменить текст рекомендации, не нужно
трогать код движка.

## Установка

```bash
pip install "fstec-lint @ git+https://github.com/Desloft-debug/fstec-lint.git"
```

Или для разработки:

```bash
git clone https://github.com/Desloft-debug/fstec-lint.git
cd fstec-lint
pip install -e ".[dev]"
pytest
```

## Использование

```bash
fstec-lint путь/к/проекту
fstec-lint . --format json --output report.json
fstec-lint . --format html --output report.html
fstec-lint . --format sarif --output report.sarif   # для GitHub Code Scanning
fstec-lint . --fail-on critical   # падать только на critical
fstec-lint . --fail-on none       # никогда не падать, только отчёт
```

`fstec-lint` рекурсивно ищет `docker-compose*.yml`, `Dockerfile`,
`postgresql.conf`, `pg_hba.conf`, `sshd_config` и `*.service` в указанном
каталоге. По умолчанию команда завершается кодом `1`, если найдена хотя
бы одна находка severity `high` или выше — это удобно для CI.

## Пример: до и после

В [`examples/vulnerable-stack`](examples/vulnerable-stack) — заведомо
дырявый Docker Compose + PostgreSQL стенд, в
[`examples/hardened-stack`](examples/hardened-stack) — тот же стек после
исправления всех находок.

```
$ fstec-lint examples/vulnerable-stack --fail-on none
[CRIT] C002 Контейнер запущен в privileged-режиме
       файл: examples/vulnerable-stack/docker-compose.yml
       где:  service:web
       мера: ЗСВ.2 / УПД.4 — Защита среды виртуализации / Управление доступом
       факт: сервис запущен с privileged: true
       фикс: Уберите privileged: true. Если приложению нужны отдельные
             привилегии — выдайте только необходимые capabilities через cap_add.

[CRIT] C004 Секрет в открытом виде в environment
       файл: examples/vulnerable-stack/docker-compose.yml
       где:  service:db
       мера: ЗНИ.1 / ИАФ.1 — Защита машинных носителей информации / ИАФ
       факт: переменная POSTGRES_PASSWORD содержит секрет в открытом виде
       фикс: Используйте docker secrets, внешний секрет-менеджер либо
             .env-файл, исключённый из системы контроля версий.

[CRIT] P001 Слабый или отсутствующий метод аутентификации в pg_hba.conf
       файл: examples/vulnerable-stack/pg_hba.conf
       где:  pg_hba: local   all       all                trust
       мера: ИАФ.1 / ИАФ.4 — Идентификация и аутентификация пользователей
       факт: метод аутентификации 'trust' разрешает подключение без пароля
       фикс: Используйте scram-sha-256 для всех записей pg_hba.conf.

[CRIT] C011 Незащищённый Docker Engine API опубликован наружу
       файл: examples/vulnerable-stack/docker-compose.yml
       где:  service:web
       мера: ЗСВ.2 / ЗПИ.1 — Защита среды виртуализации / Защита API (новая
             группа мер, введена приказом ФСТЭК №117)
       приказ: №117 (ГИС, с 01.03.2026, группа ЗПИ отсутствовала в №17)
       факт: порт 2375:2375 — доступ к нему эквивалентен root на хосте
       фикс: Не публикуйте сокет Docker наружу; используйте TLS (--tlsverify).

[HIGH] S001 Разрешён вход root по SSH
       файл: examples/vulnerable-stack/sshd_config
       где:  sshd_config: PermitRootLogin
       мера: УПД.4 / ИАФ.1 — Управление доступом / Идентификация и аутентификация
       факт: PermitRootLogin yes — вход root по SSH разрешён
       фикс: Установите PermitRootLogin no, используйте sudo от именного аккаунта.

[HIGH] U001 Сервис выполняется от root
       файл: examples/vulnerable-stack/app.service
       где:  [Service]: User
       мера: УПД.4 / ЗТС.3 — Управление доступом / Защита технических средств
       факт: User не задан или равен root — процесс выполняется от root
       фикс: Заведите отдельного системного пользователя (User=<имя>).

[CRIT] D005 curl/wget передаётся напрямую в shell
       файл: examples/vulnerable-stack/Dockerfile
       где:  Dockerfile:5: RUN
       мера: ОЦЛ.1 / АНЗ.1 — Обеспечение целостности / Анализ уязвимостей
       факт: RUN curl -sSL https://get.example.com/install.sh | bash —
             вывод curl/wget передаётся напрямую в shell без проверки
       фикс: Скачайте скрипт отдельно, проверьте sha256sum/GPG-подпись.

... ещё 40 находок ...

Итого находок: 47 (critical=11, high=10, medium=16, low=10)
```

```
$ fstec-lint examples/hardened-stack --fail-on high
fstec-lint: нарушений не найдено.
```

Что изменилось между стендами: непривилегированный `user`, `read_only` +
`tmpfs`, `no-new-privileges`, секреты вынесены в `docker secrets`, порты
привязаны к `127.0.0.1`, образы закреплены по версии, добавлены лимиты
ресурсов (`deploy.resources.limits`) и `healthcheck`, `pg_hba.conf` и
`postgresql.conf` переведены на `scram-sha-256` и `ssl = on`, включено
логирование подключений и аудит DDL (`log_statement = 'ddl'`), задан
`statement_timeout`, в `sshd_config` отключены root-логин и
парольная аутентификация, systemd-юнит запускается от отдельного
пользователя с `NoNewPrivileges`/`ProtectSystem`/`PrivateTmp`/`ProtectHome`,
а Dockerfile получил `USER`, `HEALTHCHECK`, закреплённый тег базового
образа и убрал `curl | bash` и секрет в `ARG`. Сравните
[`examples/vulnerable-stack/docker-compose.yml`](examples/vulnerable-stack/docker-compose.yml)
и
[`examples/hardened-stack/docker-compose.yml`](examples/hardened-stack/docker-compose.yml)
построчно.

## Использование в GitHub Actions

```yaml
name: fstec-lint
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Desloft-debug/fstec-lint@main
        with:
          path: .
          format: html
          output: fstec-lint-report.html
          fail-on: high
```

Отчёт сохраняется как артефакт джобы, а джоба падает при находках
`high`/`critical` — так проблему видно на этапе PR, а не при подготовке
к аттестации.

## Архитектура

```
fstec_lint/
├── parsers/        # compose/dockerfile/postgres/sshd/systemd файлы → dict
├── checks/         # логика проверок: parsed dict → список находок
├── rules/*.yaml     # метаданные правил: severity, мера ФСТЭК, remediation
├── engine.py       # находит файлы, связывает checks + rules, отдаёт Finding[]
├── reporters/      # text / json / html / sarif
└── cli.py          # argparse-обвязка + exit code для CI
```

Правило = запись в YAML (`id`, `severity`, `measure`, `orders`,
`description`, `remediation`) + функция-проверка в `checks/*.py`,
зарегистрированная по тому же `id`. Новое правило почти всегда — это
новая функция на 5–10 строк плюс блок в YAML, без изменений в движке.
Проверки для pg_hba.conf и postgresql.conf разнесены по двум отдельным
реестрам (`PG_HBA_REGISTRY` / `POSTGRESQL_CONF_REGISTRY`), так как
работают с данными разной формы (список записей vs. словарь параметров)
— это ловит mypy на этапе CI, если проверку случайно зарегистрируют не
там. Добавление нового типа файла (как sshd_config, systemd-юниты или
Dockerfile) сводится к: парсер в `parsers/`, реестр проверок в
`checks/`, YAML с правилами в `rules/` и один вызов `_run_registry(...)`
в `engine.scan`.

## Проверка качества кода

Каждый пуш и PR прогоняются через:

- `ruff check` — линт (импорты, неиспользуемый код, современный синтаксис);
- `ruff format --check` — единый стиль форматирования;
- `mypy --ignore-missing-imports` — статическая проверка типов;
- `pytest` на Python 3.10/3.11/3.12 — 103 теста, включая юнит-тесты на
  каждое правило и end-to-end проверку обоих примеров-стендов;
- самосканирование `examples/vulnerable-stack` и `examples/hardened-stack`
  как smoke-тест всего пайплайна.

Локально то же самое:

```bash
pip install -e ".[dev]"
ruff check fstec_lint tests
ruff format --check fstec_lint tests
mypy fstec_lint --ignore-missing-imports
pytest -v
```

## Roadmap

- [x] Парсер docker-compose + 10 правил, текстовый вывод
- [x] PostgreSQL (`postgresql.conf`, `pg_hba.conf`) + YAML-движок правил
- [x] HTML-отчёт, JSON-экспорт, уязвимый/защищённый стенды
- [x] Готовый GitHub Action, тесты (pytest)
- [x] Ещё 7 правил (Docker API, лимиты ресурсов, healthcheck, debug-режим,
      чувствительные точки монтирования, аудит DDL, statement_timeout) +
      явная привязка каждого правила к действующему приказу (`orders`)
- [x] `ruff` + `mypy` в CI
- [x] Правила для `sshd_config` (6 правил) и юнитов systemd (5 правил)
- [x] SARIF-экспорт для GitHub Code Scanning (`--format sarif`)
- [x] Правила для Dockerfile (6 правил: root-пользователь, `ADD` по URL,
      секрет в `ARG`, незакреплённый `FROM`, `curl \| sh`, нет `HEALTHCHECK`)
- [ ] Актуализировать номера мер после официальной публикации приказа
      взамен №21 (проект от 24.07.2026, см. «Правовой статус» — статус
      перепроверяется периодически, на 01.09.2026 приказ всё ещё не
      зарегистрирован в Минюсте)

## Лицензия

MIT, см. [LICENSE](LICENSE).

---

## English

`fstec-lint` is a static infrastructure auditor for Docker Compose,
Dockerfile, PostgreSQL, sshd_config and systemd units that maps each of
its **40 rules** to a specific control from Russia's FSTEC compliance
framework for personal data systems and state information systems.

Existing scanners (Docker Bench, Lynis, Trivy, Checkov) map findings to
CIS Benchmarks or NIST controls. Nothing maps a misconfiguration directly
onto a specific FSTEC measure code, which is exactly what a compliance
engineer needs before certification. `fstec-lint` fills that gap:
finding → FSTEC measure code → concrete remediation.

**Regulatory status (as of 2026-09-01):** Order No. 17 (state information
systems) has been **repealed** and replaced by **Order No. 117** (in
force since 2026-03-01), which expands the measure set to 18 groups and
adds new mandatory groups such as ЗПИ (API protection) — rule C011
(exposed Docker API) explicitly references it. Order No. 21 (personal
data) is technically still in force, but a draft order repealing it
entirely was published 2026-07-24 and public comment closed 2026-08-08;
its originally planned effective date (2026-09-01) has now arrived, but
as of this writing it still has not been registered with the Ministry of
Justice, so that date is slipping. See the Russian "Правовой статус"
section above for sources and details — every rule carries an `orders`
field pointing to the specific document(s) it maps to.

**Disclaimer:** this tool helps you prepare for and self-check against
compliance requirements; it does not replace formal certification and is
not a certified security product. Rule-to-measure mappings are
indicative — verify them against the current edition of the order and
your own threat model before relying on them.

**Code quality:** every push runs `ruff check`, `ruff format --check`,
`mypy --ignore-missing-imports` and `pytest` (103 tests) across Python
3.10–3.12, plus a self-scan of both example stacks as a pipeline smoke
test.

Quick start:

```bash
pip install "fstec-lint @ git+https://github.com/Desloft-debug/fstec-lint.git"
fstec-lint . --format html --output report.html --fail-on high
```

See the table above (`Что проверяется`) for the full rule list, and
[`examples/`](examples) for a deliberately vulnerable stack next to its
hardened counterpart, with the exact `fstec-lint` output for both.
