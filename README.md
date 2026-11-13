# fstec-lint

[![CI](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Статический анализатор конфигураций инфраструктуры со справочной привязкой находок к мерам защиты ФСТЭК. Проверяет файлы локально, указывает проблемные настройки и предлагает исправления. Подходит для проверки изменений в CI и подготовки материалов к аудиту.

**Текущая версия в исходниках — `1.1.1.dev0`, кандидат разработки.** В каталоге **56 правил**. Это версия пакета, а не название ветки или опубликованного релиза. Требуется **Python 3.10+**; матрица CI включает Python 3.10, 3.11 и 3.12.

Инструмент не заменяет аттестацию и не является сертифицированным средством защиты информации. Нормативные ссылки — справочные метаданные правил: их применимость и актуальность необходимо проверять по первоисточникам, модели угроз и условиям конкретной системы. Тесты целостности каталога не заменяют такую проверку.

## Что проверяется

| Конфигурация | Правила | Основные проверки |
|---|---|---|
| Docker Compose | C001–C017 — 17 | root, privileged, capabilities, секреты, порты, образы, сети, тома, Docker API, ресурсы, healthcheck и журналирование |
| Dockerfile | D001–D006 — 6 | USER, удалённый ADD, секреты в ARG, версия базового образа, передача curl/wget в shell, HEALTHCHECK |
| PostgreSQL | P001–P008 — 8 | аутентификация и адреса в HBA, listen_addresses, TLS, алгоритм хранения паролей, журналирование и statement_timeout |
| SSH | S001–S008 — 8 | root-логин, пароли, пустые пароли, протокол, X11, число попыток входа, AuthenticationMethods и LogLevel |
| systemd | U001–U005 — 5 | User, NoNewPrivileges, ProtectSystem, PrivateTmp и ProtectHome |
| dotenv | E001–E003 — 3 | секреты, режим отладки и отключение защиты TLS |
| Linux | A001–A003, R001 — 4 | срок действия и сложность паролей, неактивные учётные записи и отправка журналов |
| nginx | N001–N004 — 4 | TLS, autoindex, access_log и ограничение частоты запросов |
| Postfix | M001 — 1 | наличие настройки фильтрации входящей почты |

Проверки оценивают обнаруженные параметры файлов. Они не подтверждают состояние работающих сервисов, эффективность внешних средств защиты или полноту конфигурации системы.

Полный каталог с severity, описаниями, рекомендациями и нормативными полями:

```bash
fstec-lint --list-rules
fstec-lint --list-rules --format json --output rules.json
```

## Установка

Установка из выбранной рабочей копии репозитория:

```bash
git clone https://github.com/Desloft-debug/fstec-lint.git
cd fstec-lint
```

Перед установкой переключитесь на нужную ветку, тег или коммит. Воспроизводимая проверка должна использовать конкретную ревизию; команды ниже устанавливают именно текущий checkout.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\fstec-lint.exe --version
.\.venv\Scripts\fstec-lint.exe . --production-only
```

**Linux:**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/fstec-lint --version
.venv/bin/fstec-lint . --production-only
```

Единственная объявленная runtime-зависимость — PyYAML. DOCX формируется стандартной библиотекой Python, дополнительный пакет для него не требуется.

В дальнейших примерах `fstec-lint` означает команду из установленного окружения. Её также можно запускать как `python -m fstec_lint`, используя соответствующий интерпретатор.

## Быстрый старт

```bash
# Проверить каталог или отдельный файл
fstec-lint ./deploy
fstec-lint ./deploy/Dockerfile

# Сохранить отчёт
fstec-lint ./deploy --format html --output report.html
fstec-lint ./deploy --format sarif --output report.sarif
fstec-lint ./deploy --format docx --output report.docx

# Порог ошибки CI: low, medium, high, critical или none
fstec-lint ./deploy --fail-on high

# Выбрать правила и исключить часть из них
fstec-lint ./deploy --select "C0*,D0*" --ignore C009,C013

# Исключить пути или вложенные каталоги с примерами и тестами
fstec-lint . --exclude "tests/fixtures/*"
fstec-lint . --production-only

# Фильтр по базовому набору мер УЗ из каталога проекта
fstec-lint ./deploy --uz 3
```

По умолчанию сканируется текущий каталог, формат отчёта — `text`, порог `--fail-on` — `high`. `--ignore` применяется после `--select`. Неизвестный ID или шаблон, которому не соответствует ни одно правило, приводит к коду 2.

`--uz` принимает значения 1–4 и фильтрует правила по сохранённым в проекте базовым наборам мер приказа №21. Он не определяет уровень защищённости системы и не заменяет адаптацию набора мер.

### Какие файлы обнаруживаются

- Compose: `docker-compose*.yml`, `docker-compose*.yaml`, `compose.yml`, `compose.yaml`, `compose.override.yml`, `compose.override.yaml`.
- Dockerfile: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`.
- PostgreSQL и SSH: `postgresql.conf`, `pg_hba.conf`, `sshd_config`.
- systemd: `*.service`.
- dotenv: `.env`, `.env.*`, `*.env`.
- Linux: `login.defs`, `pwquality.conf`, фрагменты `pwquality.conf.d/*.conf`, `default/useradd`, `rsyslog.conf`.
- nginx: `nginx.conf`, а также поддерживаемые фрагменты в `nginx/conf.d` и `nginx/sites-enabled`.
- Postfix: `main.cf` в каталоге с именем `postfix`.

Тип файла определяется по имени и расположению. Произвольный файл `.conf` не становится входом PostgreSQL только потому, что указан явно; он может читаться через поддерживаемый Include.

При рекурсивном обходе пропускаются служебные и сторонние каталоги, например `.git`, `.venv`, `node_modules`, `vendor` и кэши инструментов. `--production-only` дополнительно исключает вложенные `test/tests`, `fixture/fixtures`, `example/examples`, `demo/demos`. Это фильтрация по именам, а не определение реально используемой конфигурации. Явно выбранный корень или файл не исключается только из-за своего имени.

## Форматы отчётов и коды возврата

| Формат | Назначение |
|---|---|
| `text` | Читаемый отчёт в терминале |
| `json` | Массив находок для последующей обработки |
| `html` | HTML-отчёт |
| `sarif` | Отчёт для инструментов, поддерживающих SARIF |
| `passport` | Текстовые паспорта уязвимостей |
| `docx` | Документ Word; обязателен `--output` |

Текстовые форматы по умолчанию выводятся в stdout; `--output` сохраняет отчёт в файл. Диагностика ошибок и сведения о подавленных находках выводятся в stderr. JSON содержит находки: пустой массив сам по себе не доказывает успешность сканирования — проверяйте код возврата и stderr.

| Код | Значение |
|---|---|
| `0` | Обработка завершена без ошибок и без находок на выбранном пороге или выше |
| `1` | Есть находки на выбранном пороге или выше |
| `2` | Ошибка вызова, загрузки правил, baseline или записи отчёта |
| `3` | Неполный анализ: часть входов не удалось обработать |

Код **1 имеет приоритет над 3**: наличие ошибки разбора не отменяет уже найденные нарушения. `--fail-on none` отключает порог находок, но ошибки разбора по-прежнему дают код 3. Код 0 при пороге `high` не означает отсутствия находок `medium` и `low`.

## Работа с baseline

Baseline фиксирует просмотренные и принятые находки, чтобы последующие проверки показывали новые проблемы.

```bash
# Сначала просмотреть результаты
fstec-lint ./deploy --format html --output review.html --fail-on none

# Записать согласованный набор известных находок
fstec-lint ./deploy --write-baseline .fstec-lint-baseline.json

# Проверять изменения относительно него
fstec-lint ./deploy --baseline .fstec-lint-baseline.json --fail-on high
```

`--write-baseline` возвращает 0 при успешной полной записи независимо от severity. При ошибках сканирования файл может содержать неполный набор находок, а команда вернёт 3. Такой результат нужно проверить перед принятием в качестве baseline.

Формат JSON остаётся **v3**. Идентификатор находки включает правило, путь и location; текст рекомендации и номер строки в него не входят. В fingerprint разделители пути приведены к `/`. Запускайте команды из одного корня проекта, чтобы относительные пути совпадали.

- **Docker D002/D005:** location содержит хеш нормализованной команды после удаления известных форм учётных данных и номер повторения одинаковой команды. Отдельные строки комментариев и сдвиг строк не меняют идентификатор. Замена адреса загрузки или другой значимой части команды остаётся новой находкой. Порядок одинаковых команд имеет значение.
- **HBA P001/P002:** location зависит от структурных полей записи и номера её повторения; опции вроде пароля LDAP не входят в идентификатор.
- **Старые текстовые Docker/HBA-записи:** CLI сопоставляет их только с выбранными исходниками и текущими находками. Требуется точное однозначное совпадение. Файл baseline при этом не переписывается.
- Если запись не удалось однозначно сопоставить, возвращается код 2 с рекомендацией проверить результаты и выполнить `--write-baseline`. Старые Docker-адреса только с номером инструкции не позволяют восстановить соответствие безопасно.

Хеш не является шифрованием. Неизвестные формы секретов могут участвовать в идентификаторе, а предсказуемые значения — подбираться перебором. Контролируйте доступ к baseline и отчётам; подробности — в [границах безопасности](docs/security.md).

### Подавление в конфигурации

```yaml
services:
  app:
    image: nginx:1.27
    # fstec-lint: ignore C009
    read_only: false
```

Комментарий `fstec-lint: ignore` принимает ID и шаблоны правил. Без списка он подавляет все находки в своей области действия. Общий механизм учитывает собственную и следующую строку; для Compose дополнительно используются строки заголовка сервиса и соответствующего поля. Причину исключения стоит фиксировать рядом с комментарием и проверять при изменении конфигурации.

Для исключения правила во всём запуске используйте `--ignore`; для принятия конкретного набора известных находок — baseline.

## Ограничения анализа

- **Compose:** файлы анализируются отдельно. Объединение основного и override-файлов не реализовано. Обнаруженная пара, а также `include` или `extends`, приводят к сообщению о неполном анализе. Поддержка `!reset`/`!override` в отдельном файле не означает поддержку Compose merge.
- **PostgreSQL:** поддерживаются `include`, `include_if_exists` и `include_dir` в пределах выбранного дерева, с ограничениями глубины, объёма и числа файлов. Неподдерживаемые продолжения HBA и некорректные проверяемые параметры не считаются чистым разбором. См. [PostgreSQL Include](docs/postgresql-includes.md).
- **SSH:** Include раскрывается в пределах выбранного дерева. Относительная база — каталог основного файла, а не системный `/etc/ssh`; полная семантика OpenSSH не воспроизводится.
- **nginx, rsyslog и другие форматы:** реализован разбор необходимого для проверок подмножества синтаксиса, а не полная модель сервиса.
- **Ресурсы:** YAML Compose и правил ограничен по размеру и сложности графа; циклы и превышение бюджета дают контролируемую ошибку. JSON baseline и чтение через общий ограниченный читатель также имеют лимиты.
- **Границы чтения:** Compose, Dockerfile, HBA, поддерживаемые включаемые файлы и повторное чтение комментариев подавления используют проверку открытого файла до чтения. На Windows проверяется дескриптор, на Linux — `/proc/self/fd`; невозможность проверки означает отказ. Это не полная атомарная изоляция дерева. Не сканируйте дерево, одновременно изменяемое недоверенным субъектом.

Линтер не запускает Docker, shell-команды или проверяемые сервисы. Он не заменяет проверку эффективной конфигурации, сетевой доступности, работающей аутентификации и организационных мер.

## GitHub Actions

Пример использования ветки кандидата:

```yaml
name: Configuration audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Desloft-debug/fstec-lint@release/1.0.2-candidate
        with:
          path: deploy
          format: html
          output: fstec-lint-report.html
          fail-on: high
```

Замените `deploy` на каталог конфигураций своего проекта. В постоянном workflow закрепите проверенный commit SHA вместо изменяемой ветки. Action устанавливает ревизию, с которой он вызван, запускает CLI и пытается загрузить отчёт как артефакт даже при падении шага сканирования.

Обёртка предоставляет параметры `path`, `format`, `output`, `fail-on`. Для baseline, выбора правил и других опций установите пакет отдельным шагом и вызовите CLI напрямую.

## Примеры

В репозитории находятся два стенда:

- [vulnerable-stack](examples/vulnerable-stack) — конфигурации с намеренными нарушениями;
- [hardened-stack](examples/hardened-stack) — пример исправлений в пределах проверяемых правил.

```bash
fstec-lint examples/vulnerable-stack --fail-on high
# Ожидаемый код: 1

fstec-lint examples/hardened-stack --fail-on high
# Ожидаемый код: 0
```

Нулевой код защищённого примера относится к правилам и порогу этого запуска, а не к полной защищённости системы.

## Разработка и проверки

Зависимости разработки устанавливаются из корня рабочей копии:

```bash
python -m pip install -e ".[dev]" -c constraints.txt
python -m ruff check fstec_lint tests
python -m ruff format --check fstec_lint tests
python -m mypy --platform linux fstec_lint
python -m mypy --platform win32 fstec_lint
```

Перед pytest задайте один новый временный каталог для четырёх переменных окружения — это проверяется тестами и настроено в CI.

**Windows PowerShell, с интерпретатором созданного окружения:**

```powershell
$testTemp = Join-Path ([System.IO.Path]::GetTempPath()) ('fstec-tests-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $testTemp | Out-Null
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:TMPDIR = $testTemp
$env:PYTEST_DEBUG_TEMPROOT = $testTemp
.\.venv\Scripts\python.exe -m pytest tests -v --cov=fstec_lint --cov-report=term-missing
```

**Linux:**

```bash
test_tmp="$(mktemp -d)"
TEMP="$test_tmp" TMP="$test_tmp" TMPDIR="$test_tmp" PYTEST_DEBUG_TEMPROOT="$test_tmp" \
  .venv/bin/python -m pytest tests -v --cov=fstec_lint --cov-report=term-missing
```

CI запускается для pull request и push в `main`: сборка и установка wheel, проверка Action, Ruff, Mypy, аудит зависимостей, тесты Python 3.10–3.12 и самосканирование примеров. Порог покрытия — **90%**; матрица тестов настроена с `fail-fast: false`.

Подтверждённый локальный прогон исправлений от **13 ноября 2026**, Windows / Python 3.10.11: **1496 passed, 86 skipped**, без падений, покрытие **94,41%**. Ruff, форматирование, обе статические проверки Mypy, сборка и проверка wheel прошли. Это не подтверждение полного Linux-прогона: актуальный результат GitHub CI нужно смотреть для конкретного коммита.

Команды сборки, сведения об аудите и история проверок — в [docs/development.md](docs/development.md) и [docs/verification.md](docs/verification.md).

## Документация

| Тема | Документ |
|---|---|
| Архитектура и добавление правил | [architecture.md](docs/architecture.md) |
| Ограничения чтения, ресурсы и baseline | [security.md](docs/security.md) |
| PostgreSQL Include | [postgresql-includes.md](docs/postgresql-includes.md) |
| Разбор dotenv | [dotenv.md](docs/dotenv.md) |
| Связи правил с предметами мер | [rules-subjects.md](docs/rules-subjects.md) |
| Нормативные поля приказа №117 | [measures-117.md](docs/measures-117.md) |
| Фильтрация по уровням защищённости ПДн | [pdn.md](docs/pdn.md) |
| Аутентификация и severity | [authentication.md](docs/authentication.md) |
| Материалы для оценки защищённости и зрелости | [kzi.md](docs/kzi.md), [maturity.md](docs/maturity.md) |
| Паспорта уязвимостей | [passport.md](docs/passport.md) |
| Самооценка процессов разработки | [rbpo.md](docs/rbpo.md) |
| Методика внешних сравнений и исторические результаты | [benchmarks/README.md](benchmarks/README.md) |

Метаданные каталога содержат ссылки на приказы №117 и №21, методические документы и стандарты. Разделы документации отражают принятую в проекте модель привязок; они не являются заключением о действующем правовом статусе документов или доказательством соответствия.

Сообщить об уязвимости: [SECURITY.md](SECURITY.md). История изменений: [CHANGELOG.md](CHANGELOG.md).

## English summary

`fstec-lint` is a local static configuration analyzer with **56 rules** covering Docker Compose, Dockerfiles, PostgreSQL, SSH, systemd, dotenv, selected Linux settings, nginx and Postfix. Findings include severity, remediation and reference mappings to FSTEC measures.

The source version is **`1.1.1.dev0`**, a development candidate. Python **3.10+** is required. Install from the desired checkout with `python -m pip install -e .`, then run:

```bash
fstec-lint ./deploy --format html --output report.html --fail-on high
fstec-lint --list-rules
fstec-lint ./deploy --write-baseline baseline.json
fstec-lint ./deploy --baseline baseline.json
```

Output formats are `text`, `json`, `html`, `sarif`, `passport` and `docx`; DOCX requires `--output`. Exit codes are **0** for a complete scan below the selected failure threshold, **1** for findings at or above it, **2** for usage or processing setup errors, and **3** for incomplete analysis. Code 1 takes precedence over 3; `--fail-on none` does not hide parsing errors.

Baseline v3 supports stable Docker identities and exact matching of legacy text-based Docker/HBA entries against selected sources. Ambiguous entries are rejected. Reports and baselines still require access controls; hashing is not encryption.

Compose merge is unsupported. PostgreSQL and SSH includes are limited to the selected tree and supported syntax. The analyzer does not execute configuration commands or certify a running system. Regulatory mappings are reference information and require independent verification.

The documented local Windows run passed **1496 tests**, skipped **86**, and reached **94.41% coverage**. Consult the CI run for the exact commit for Linux results.

## Лицензия

[MIT](LICENSE).
