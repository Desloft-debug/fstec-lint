# fstec-lint

[![CI](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Desloft-debug/fstec-lint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Проверка конфигураций инфраструктуры до развёртывания.** fstec-lint находит
рискованные настройки в файлах проекта, показывает исходный файл и строку,
предлагает исправление и приводит справочную ссылку на меру ФСТЭК.
Линтер не запускает контейнеры, команды из конфигураций или проверяемые сервисы.

Эта ветка содержит **1.1 (`1.1.0.dev0`)** и **62 правила**. Нужен Python 3.10 или новее.

## Быстрый старт

Из корня репозитория, после переключения на нужную ветку или тег:

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\fstec-lint.exe menu
```

**Linux**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/fstec-lint menu
```

В меню укажите путь к проекту или отдельному файлу. Программа покажет находки
в терминале и предложит сохранить текстовый отчёт. Меню не требует браузера
и не создаёт базу данных.

В следующих примерах используйте команду `fstec-lint` из своего окружения
(или путь к ней из блока выше).

```bash
# Проверка тестового стенда и HTML-отчёт
fstec-lint examples/vulnerable-stack --format html --output review.html --fail-on none

# Строгая проверка своего проекта
fstec-lint ./deploy --strict-scope --require-input --no-inline-suppressions --fail-on high

# Каталог правил без сканирования
fstec-lint --list-rules
```

Откройте `review.html` в браузере: сверху сводка по уровням, ниже находки
по файлам, рекомендации и информация о неполной проверке. Отдельного
графического интерфейса для запуска проверок нет.

## Что проверяется

| Вход | Правила | Примеры проверок |
| --- | --- | --- |
| Docker Compose | C001–C020 | root, privileged, capabilities, опубликованные порты, Docker API, PID/IPC хоста |
| Dockerfile | D001–D006 | пользователь, удалённый ADD, секреты в ARG, версия базового образа, HEALTHCHECK |
| PostgreSQL | P001–P009 | методы HBA, TLS, журналирование, хранение паролей и таймаут запросов |
| OpenSSH | S001–S008 | вход root, пароли, пустые пароли, попытки входа и методы аутентификации |
| systemd | U001–U007 | User, NoNewPrivileges, ProtectSystem, PrivateTmp, ProtectHome, защита параметров и модулей ядра |
| dotenv | E001–E003 | секреты, отладка и отключение проверки TLS |
| Linux | A001–A003, R001 | настройки паролей, неактивные учётные записи, отправка журналов |
| nginx | N001–N004 | TLS, autoindex, access_log и ограничения запросов |
| Postfix | M001 | настройка фильтрации входящей почты |

- **PostgreSQL:** читает локальные включения в `postgresql.conf` и
  `pg_hba.conf` (синтаксис HBA PostgreSQL 16+). Находка указывает на фрагмент,
  где задана настройка. Соседний `postgresql.auto.conf` применяется после основного файла. [Поддерживаемые включения](docs/postgresql-includes.md).
- **systemd:** учитывает локальные общие, префиксные, шаблонные и именные drop-in
  для проверяемых одиночных директив. [Порядок применения и ограничения](docs/systemd-drop-ins.md).
- **Compose:** по умолчанию файлы анализируются отдельно. Повторяемый
  `--compose-file` позволяет явно задать порядок локальных слоёв;
  поддерживается слияние отдельных полей, в том числе `environment`,
  `healthcheck` и литеральных портов. Неоднозначные случаи остаются неполными.
  [Примеры и ограничения](docs/review-acceptance.md).

`--select C005,P001` выбирает правила, `--ignore` исключает правила,
`--exclude` исключает пути, `--production-only` пропускает вложенные
каталоги тестов и примеров по имени. Список всех опций: `fstec-lint --help`.

## Отчёты и CI

`text` и `html` предназначены для чтения, `json` сохраняет совместимость
со скриптами, которым нужен массив находок. Для автоматизации используйте
`json-context`: он отдельно показывает находки и неполноту проверки.
Доступны также `sarif`, `passport` и `docx` (для DOCX нужен `--output`).

| Код | Значение |
| --- | --- |
| 0 | Нет находок на заданном пороге или выше и нет зарегистрированных ошибок проверки |
| 1 | Есть находки на пороге `--fail-on` или выше; по умолчанию порог `high` |
| 2 | Ошибка вызова, подготовки или записи результата |
| 3 | Проверка неполна, а находок на выбранном пороге нет |

Код 1 имеет приоритет над 3. Если нужно отличить неполноту от результатов
проверок, смотрите stderr или поле `partial` в `json-context`. Пустой массив
в обычном JSON не доказывает, что всё было проверено. `--fail-on none`
не скрывает ошибки разбора, а `--require-input` не даёт принять пустой набор файлов
за успешную проверку.

В GitHub Actions можно вызывать CLI или использовать [Composite Action](action.yml)
с проверенным SHA версии. У обёртки загрузка отчёта в артефакты отключена по
умолчанию. Не публикуйте отчёты с данными закрытых проектов.
[CI самого репозитория](.github/workflows/ci.yml) запускается на PR и на push в
`main`. На Linux тесты запускаются на Python 3.10, 3.11 и 3.12;
на Windows добавлен отдельный прогон на Python 3.12.

**Baseline** исключает уже принятые находки из текущего отчёта:
`--write-baseline baseline.json` сохраняет набор, `--baseline baseline.json`
применяет его. Это не история прогонов и не подтверждение устранения.
`--no-inline-suppressions` отключает исключения из комментариев.

## История проверок в SQLite

База необязательна. В ней можно связать прогоны fstec-lint и импортированные тесты
JUnit с одной ревизией, а затем сравнить два прогона одного инструмента и профиля.

```bash
fstec-lint ./deploy --history-db checks.sqlite3 --project demo --revision rev-a
fstec-lint history list checks.sqlite3 --project demo
```

История отличает «исправлено» от «не удалось проверить». Одинаковый
`--run-key` для той же ревизии и инструмента не дублирует идентичный результат.
Обычная SQLite не шифруется. Для шифрования файла используйте формат
`.fsth`: требуется Python 3.11+ с поддержкой сериализации SQLite и установка
`python -m pip install -e ".[history-encryption]"`. Ключ храните отдельно;
шифрование не обнаруживает удаление файла или замену старой подлинной копией.
В историю не записываются исходники и сообщения об ошибках тестов.
[Схема, сравнение прогонов и импорт JUnit](docs/history.md).

## Границы проверки и документация

Линтер проверяет то, что видно в файлах. Он не подтверждает реальное состояние
сервисов и не заменяет аттестацию. Ссылки на меры ФСТЭК служат для навигации:
применимость нужно сверять отдельно. `--gis-class` даёт контекст в `json-context` и SARIF,
не определяет класс и не фильтрует находки.

- [Нормативные источники и сила привязок](docs/regulatory-2026.md)
- [Обработка входов, ресурсы и baseline](docs/security.md)
- [Разработка и тестирование](docs/development.md)
- [Архитектура и добавление правил](docs/architecture.md)
- [Методика внешних сравнений](benchmarks/README.md)
- [История изменений](CHANGELOG.md) · [Сообщить об уязвимости](SECURITY.md)

## English summary

fstec-lint is a local static infrastructure configuration checker for Python 3.10+.
This branch contains the 1.1 development build (`1.1.0.dev0`) with 62 rules.
Run `fstec-lint menu` for the terminal menu, or use
`fstec-lint ./deploy --format html --output report.html` for an HTML report.
Use `json-context` to distinguish findings from incomplete analysis in CI.
Optional local history can store scan results and import JUnit outcomes
under the same revision. It supports SQLite and an authenticated encrypted file. This tool does not run checked services or certify them.

[MIT](LICENSE).
