# fstec-lint

[![CI](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Статический аудит инфраструктуры (Docker Compose, PostgreSQL) с привязкой
каждой находки к конкретной мере защиты информации из приказов ФСТЭК России
**№21** (защита ПДн) и **№17** (защита ГИС).

Аналоги вроде Docker Bench, Lynis, Trivy или Checkov отлично находят
проблемы, но мапят их на CIS Benchmarks / NIST. Ответа на вопрос
«какую меру из приказа ФСТЭК закрывает этот фикс» они не дают, а именно
он нужен на этапе подготовки к аттестации ГИС или к оценке соответствия
ИСПДн. `fstec-lint` закрывает этот разрыв: находка → конкретная мера
(ИАФ, УПД, ЗСВ, РСБ, ЗИС и т.д.) → как исправить.

> **Важно.** Инструмент помогает готовиться к оценке соответствия и
> ускоряет самопроверку перед аттестацией, но не заменяет её и не
> является сертифицированным средством защиты информации. Соответствие
> находок конкретным пунктам приказов носит справочный характер —
> перед использованием в реальном проекте сверьте номера мер с
> действующей редакцией приказа и вашей моделью угроз.

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

**PostgreSQL** (`postgresql.conf` / `pg_hba.conf`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| P001 | `trust`/`md5` в `pg_hba.conf` | ИАФ.1 / ИАФ.4 |
| P002 | Подключение разрешено с `0.0.0.0/0` | УПД.4 |
| P003 | `listen_addresses = '*'` | ЗИС.20 |
| P004 | Логирование подключений выключено | РСБ.1 / РСБ.3 |
| P005 | `ssl = off` | ЗИС.17 / ЗНИ.1 |
| P006 | `password_encryption = md5` | ИАФ.1 |

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
fstec-lint . --fail-on critical   # падать только на critical
fstec-lint . --fail-on none       # никогда не падать, только отчёт
```

`fstec-lint` рекурсивно ищет `docker-compose*.yml`, `postgresql.conf` и
`pg_hba.conf` в указанном каталоге. По умолчанию команда завершается кодом
`1`, если найдена хотя бы одна находка severity `high` или выше — это
удобно для CI.

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

... ещё 20 находок ...

Итого находок: 23 (critical=7, high=6, medium=8, low=2)
```

```
$ fstec-lint examples/hardened-stack --fail-on high
fstec-lint: нарушений не найдено.
```

Что изменилось между стендами: непривилегированный `user`, `read_only` +
`tmpfs`, `no-new-privileges`, секреты вынесены в `docker secrets`, порты
привязаны к `127.0.0.1`, образы закреплены по версии, `pg_hba.conf` и
`postgresql.conf` переведены на `scram-sha-256` и `ssl = on`, включено
логирование подключений. Сравните
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
├── parsers/        # docker-compose.yml, postgresql.conf, pg_hba.conf → dict
├── checks/         # логика проверок: parsed dict → список находок
├── rules/*.yaml     # метаданные правил: severity, мера ФСТЭК, remediation
├── engine.py       # находит файлы, связывает checks + rules, отдаёт Finding[]
├── reporters/      # text / json / html
└── cli.py          # argparse-обвязка + exit code для CI
```

Правило = запись в YAML (`id`, `severity`, `measure`, `description`,
`remediation`) + функция-проверка в `checks/*.py`, зарегистрированная по
тому же `id`. Новое правило почти всегда — это новая функция на 5–10
строк плюс блок в YAML, без изменений в движке.

## Roadmap

- [x] Парсер docker-compose + 10 правил, текстовый вывод
- [x] PostgreSQL (`postgresql.conf`, `pg_hba.conf`) + YAML-движок правил
- [x] HTML-отчёт, JSON-экспорт, уязвимый/защищённый стенды
- [x] Готовый GitHub Action, тесты (pytest)
- [ ] Правила для `sshd_config` и юнитов systemd
- [ ] Профили нескольких редакций приказов (актуальная сверка номеров мер)
- [ ] SARIF-экспорт для GitHub Code Scanning

## Лицензия

MIT, см. [LICENSE](LICENSE).

---

## English

`fstec-lint` is a static infrastructure auditor for Docker Compose and
PostgreSQL configurations that maps every finding to a specific control
from Russia's FSTEC compliance orders **No. 21** (personal data systems)
and **No. 17** (state information systems) — the same regulatory
framework used across Russian government, financial, and personal-data
processing IT infrastructure.

Existing scanners (Docker Bench, Lynis, Trivy, Checkov) map findings to
CIS Benchmarks or NIST controls. Nothing maps a misconfiguration directly
onto a specific FSTEC measure code, which is exactly what a compliance
engineer needs before certification. `fstec-lint` fills that gap:
finding → FSTEC measure code → concrete remediation.

**Disclaimer:** this tool helps you prepare for and self-check against
compliance requirements; it does not replace formal certification and is
not a certified security product. Rule-to-measure mappings are
indicative — verify them against the current edition of the order and
your own threat model before relying on them.

Quick start:

```bash
pip install "fstec-lint @ git+https://github.com/Desloft-debug/fstec-lint.git"
fstec-lint . --format html --output report.html --fail-on high
```

See the table above (`Что проверяется`) for the full rule list, and
[`examples/`](examples) for a deliberately vulnerable stack next to its
hardened counterpart, with the exact `fstec-lint` output for both.
