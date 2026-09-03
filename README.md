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

### Статус кодов мер в правилах

> Коды мер в `rules/*.yaml` проставлены по приказу ФСТЭК России № 17
> (утратил силу 01.03.2026). Приказ № 117 и методический документ к нему
> изменили состав и нумерацию мер; соответствие кодов не сверено. Поле
> `orders` в текущем виде отражает историческую привязку и не является
> утверждением о соответствии действующим требованиям.

Переустановка кодов ждёт перечня подмер из методического документа —
пересказ вместо таблицы здесь хуже, чем отсутствие таблицы. Что каждое
правило проверяет фактически, без нормативных утверждений, описано в
[`docs/rules-subjects.md`](docs/rules-subjects.md): по этой таблице
привязка восстанавливается сопоставлением списков, когда документ будет
на руках.

Практический вывод: сохранились ли коды мер между старой и новой базой —
вопрос открытый, и утверждение «в большинстве своём сохранились» из
прошлых редакций этого README снято как непроверенное. Обзоры приказа
№117 расходятся даже в числе групп мер, поэтому нумерация правил
переустанавливается по методическому документу, а не по пересказам.
Актуализация `fstec_lint/rules/*.yaml` — первый пункт раздела «Дальше» в
Roadmap.

Ссылки ниже — обзоры, а не источник данных для правил: ни одно значение
в `rules/*.yaml` по ним не проставляется.

Источники: [CISOClub о новом приказе ФСТЭК взамен №21](https://cisoclub.ru/fstjek-rossii-gotovit-otmenu-prikaza-21-i-novuju-sistemu-zashhity-personalnyh-dannyh/), [обзор приказа №117 (Angara Security)](https://www.angarasecurity.ru/stati/analiz-prikaza-fstek-rossii-117/), [BI.ZONE о группах мер приказа №117](https://bi.zone/expertise/insights/prikaz-fstek-rossii-117-novyy-etap-zashchity-informatsii-v-gossektore/).

---

## Что проверяется

**Docker Compose** (`docker-compose.yml` / `compose.yaml`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| C001 | Контейнер без `user:` либо с `user: root` — работает от root | УПД.4 / ЗСВ.2 |
| C002 | `privileged: true` | ЗСВ.2 / УПД.4 |
| C003 | Опасные `cap_add` (`SYS_ADMIN`, `NET_ADMIN`, `ALL`...) | ЗСВ.2 |
| C004 | Пароль/токен в `environment` открытым текстом или как дефолт `${VAR:-...}` | ЗНИ.1 / ИАФ.1 |
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

Условные блоки `Match` разбираются наравне с глобальной секцией: если
`PermitRootLogin no` стоит вверху файла, а внутри `Match Address
10.0.0.0/8` он снова `yes` — это находка, и в отчёте видно, в каком
именно блоке. Директива, не заданная внутри блока, наследуется сверху и
повторно не считается, поэтому одна и та же проблема не размножается по
числу блоков.

**systemd** (`*.service`, секция `[Service]`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| U001 | Сервис выполняется от root (`User` не задан, `DynamicUser` выключен) | УПД.4 / ЗТС.3 |
| U002 | Нет `NoNewPrivileges=true` (`yes`/`on`/`1` равнозначны) | ЗСВ.2 |
| U003 | Нет `ProtectSystem=yes`/`full`/`strict` | ОЦЛ.1 |
| U004 | Нет `PrivateTmp=true` (`yes`/`on`/`1` равнозначны) | ЗСВ.2 |
| U005 | Нет `ProtectHome=true`/`read-only`/`tmpfs` | УПД.4 |

**Dockerfile** (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`):

| Правило | Проблема | Мера ФСТЭК |
|---|---|---|
| D001 | В финальном стейдже нет `USER` либо это `USER root` | УПД.4 / ЗСВ.2 |
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
pip install -e ".[dev]" -c constraints.txt
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
fstec-lint --list-rules           # каталог правил, без сканирования

fstec-lint . --write-baseline .fstec-lint-baseline.json   # зафиксировать текущий долг
fstec-lint . --baseline .fstec-lint-baseline.json         # падать только на новых находках

fstec-lint . --exclude "tests/fixtures/*" --exclude legacy  # не сканировать своё
fstec-lint . --ignore C013,C009    # выключить правила (id или glob)
fstec-lint . --select "S0*,P0*"    # проверять только SSH и PostgreSQL
fstec-lint --version
```

`fstec-lint` рекурсивно ищет `docker-compose*.yml`, `Dockerfile`,
`postgresql.conf`, `pg_hba.conf`, `sshd_config` и `*.service` в указанном
каталоге. Служебные и сторонние каталоги (`.git`, `node_modules`,
`vendor`, `.venv`, `site-packages`, `__pycache__`, кеши линтеров,
`.terraform`) пропускаются всегда — чужие конфиги правятся не вами и
только создают шум. Всё остальное исключается через `--exclude` (glob по
имени или по пути относительно корня сканирования, флаг можно повторять).

### Как выключить правило

Три способа, от точечного к глобальному.

**Комментарий в самом файле** — когда исключение относится к одному
месту и его нужно объяснить рядом с кодом:

```yaml
services:
  db:  # fstec-lint: ignore C001, C009
    image: postgres:16.4
```

Комментарий действует на свою строку и на следующую (чтобы его можно
было писать и в хвосте строки, и над ней), понимает список правил через
запятую и glob (`C0*`), а без списка — `# fstec-lint: ignore` — глушит
на этой строке всё.

Для `docker-compose.yml` работают оба места: комментарий у нарушающей
директивы глушит находку по ней, комментарий на заголовке сервиса
выводит из проверки сервис целиком.

```yaml
services:
  db:  # fstec-lint: ignore C001, C009   ← весь сервис
    image: postgres:16.4
    # fstec-lint: ignore C005            ← только находка по портам
    ports:
      - "5432:5432"
``` Работает в любом проверяемом формате: YAML,
Dockerfile, `sshd_config`, `postgresql.conf`, юниты systemd. Число
подавленных так находок печатается в stderr, чтобы «тихих» исключений не
накапливалось незаметно.

**`--ignore` / `--select`** — когда правило не подходит проекту целиком:

```bash
fstec-lint . --ignore C013          # healthcheck заводится не здесь
fstec-lint . --ignore "C009,C012"
fstec-lint . --select "S0*"         # только SSH
```

Оба принимают id и glob, через запятую или повторением флага;
`--ignore` применяется после `--select`. Шаблон, не подошедший ни к
одному правилу, — почти всегда опечатка, поэтому о нём предупреждают в
stderr. Те же флаги работают с `--list-rules`, так что выгруженный
каталог соответствует тому, что реально проверяется.

**`--baseline`** — когда правило нужное, но долг разбирается постепенно
(см. раздел ниже).

### Коды выхода

| Код | Что означает                                                        |
|-----|---------------------------------------------------------------------|
| `0` | находок выше порога `--fail-on` нет, все файлы обработаны           |
| `1` | есть находки severity `--fail-on` или выше (по умолчанию `high`)    |
| `2` | ошибка вызова: путь не найден, отчёт некуда записать, baseline повреждён, шаблон в `--select`/`--ignore` не подошёл ни к одному правилу |
| `3` | находок выше порога нет, но часть файлов не удалось обработать       |

Коды проверяются в этом порядке: **1 важнее 3**. Прогон, в котором есть и
critical-находка, и нечитаемый файл, возвращает `1` — иначе гейт,
различающий эти коды, прочитал бы такой прогон как чистый.

Пути в отчётах относительные — от каталога, из которого запущена команда.
Отчёт, снятый на ноутбуке, и отчёт из CI сравнимы построчно, а SARIF с
абсолютными путями GitHub просто не сопоставил бы с файлами репозитория.
Исключение одно: если сканируемый путь лежит **вне** текущего каталога,
относительная запись выродилась бы в цепочку `../../..`, и тогда в отчёт
идёт абсолютный путь. Baseline в этом случае непереносим между машинами —
запускайте `fstec-lint` из корня проверяемого проекта.

Код `3` намеренно отделён от `1`: битый YAML, не-UTF-8 файл с расширением
`.service`, нечитаемый каталог или сбой самой проверки — это проблема
прогона, а не проекта, и чинится она иначе, чем находка. Такой файл
пропускается с сообщением в stderr, остальные проверяются как обычно —
один мусорный файл не роняет весь скан.

Опечатка в `--select` / `--ignore` — тоже код `2`, а не предупреждение:
`fstec-lint . --select C00l` не проверяет ни одного правила, и прогон, не
проверивший ничего, не должен выглядеть как успешный аудит.

### Каталог правил

Отдельно от сканирования можно выгрузить перечень самих проверок — какие
правила вообще есть и какие группы мер ФСТЭК они затрагивают. Это тот
самый перечень, который удобно приложить к документам по оценке
соответствия:

```bash
fstec-lint --list-rules                  # текстом
fstec-lint --list-rules --format json    # машиночитаемо
```

```
Правил всего: 40

docker-compose.yml / compose.yaml (15):
  [HIGH] C001  УПД.4 / ЗСВ.2          Контейнер запускается от имени root
  [CRIT] C002  ЗСВ.2 / УПД.4          Контейнер запущен в privileged-режиме
  ...

Затронутые группы мер ФСТЭК: АНЗ (5), ЗИС (7), ЗНИ (3), ЗПИ (1), ЗСВ (11),
ЗТС (1), ИАФ (7), ОДТ (4), ОЦЛ (6), РСБ (2), УПД (10)
```

Сводка внизу честно показывает и обратное — какие группы мер инструмент
**не** закрывает (АВЗ, СОВ, ИНЦ, УКФ и др.): статический анализ конфигов
их в принципе не проверяет, и закрывать их нужно другими средствами.

### Внедрение в существующий проект: baseline

Главная проблема при подключении любого линтера к живому проекту — он
сразу даёт десятки находок, CI краснеет, и его отключают. Baseline
фиксирует текущее состояние как известный долг: сборка падает только на
**новых** находках, а старые остаются в отчёте, но не блокируют.

```bash
fstec-lint . --write-baseline .fstec-lint-baseline.json   # один раз, зафиксировать долг
git add .fstec-lint-baseline.json

fstec-lint . --baseline .fstec-lint-baseline.json         # в CI
```

```
$ fstec-lint examples/vulnerable-stack --baseline baseline.json --fail-on critical
fstec-lint: подавлено baseline-ом: 47
[CRIT] C015 Смонтирован чувствительный путь хоста
       файл: examples/vulnerable-stack/docker-compose.yml
       где:  service:db
       ...
Итого находок: 1 (critical=1)
```

Находка опознаётся по тройке «правило + файл + место» (например,
`C015 | docker-compose.yml | service:db`), пути хранятся относительными —
чтобы файл работал одинаково на машине разработчика и в CI. Ни текст
описания, ни номер строки в отпечаток не входят: ни правки формулировок в
правилах, ни вставка строки выше по файлу не должны внезапно «воскрешать»
весь зафиксированный долг. Номер строки при этом никуда не делся — он
живёт в отдельном поле находки и попадает в отчёты. Файл отсортирован и
детерминирован, поэтому его диффы читаемы на ревью — видно ровно то, что
добавили или разобрали.

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
       файл: examples/vulnerable-stack/Dockerfile:6
       где:  stage 1: RUN curl -sSL https://get.example.com/install.sh | bash
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
├── engine.py       # находит файлы, связывает checks + rules, отдаёт ScanResult
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
`checks/`, YAML с правилами в `rules/` и одна строка в списке реестров
`engine.scan`.

Проверка возвращает тройку `(location, detail, line)`: `location` —
стабильный адрес находки внутри файла (`service:db`, `stage 2: FROM
ubuntu`, `sshd_config: PermitRootLogin`), по нему считается отпечаток для
baseline; `line` — номер строки для отчётов и SARIF. Разделение
намеренное: номер строки меняется при любой правке выше по файлу, адрес
находки — нет. Номера строк дают сами парсеры (`ConfigMap` для
конфигов в формате «ключ = значение», узлы YAML для compose, позиция
инструкции для Dockerfile).

`engine.scan` возвращает `ScanResult` с находками **и** списком файлов,
которые не удалось разобрать: каждый файл парсится в своём try/except,
поэтому битый или бинарный файл виден в отчёте, но не прекращает скан.

## Проверка качества кода

Каждый пуш и PR прогоняются через:

- `ruff check` — линт (импорты, неиспользуемый код, современный синтаксис);
- `ruff format --check` — единый стиль форматирования;
- `mypy` в строгом режиме (`disallow_untyped_defs`) — статическая проверка типов;
- `pytest` на Python 3.10/3.11/3.12 — 244 теста при пороге покрытия 90%
  (фактическое — 95%), включая юнит-тесты на каждое правило, end-to-end
  проверку обоих примеров-стендов, регрессию на каждый закрытый дефект
  разбора и проверку целостности каталога правил (у каждого правила из
  YAML есть функция-проверка с тем же `id`, и наоборот — иначе правило
  молча ничего не делает);
- самосканирование `examples/vulnerable-stack` и `examples/hardened-stack`
  как smoke-тест всего пайплайна, вместе с проверкой кодов возврата:
  уязвимый стенд обязан дать код `1`, защищённый — `0`.

Локально то же самое:

```bash
pip install -e ".[dev]" -c constraints.txt
ruff check fstec_lint tests
ruff format --check fstec_lint tests
mypy fstec_lint
pytest -v
```

## Roadmap

### Сделано

- [x] Движок правил: метаданные в `rules/*.yaml`, логика проверок в
      `checks/*.py`, связь по id и тест целостности «YAML ↔ функции»
- [x] 40 правил в пяти каталогах: docker-compose (15), PostgreSQL —
      `postgresql.conf` и `pg_hba.conf` (8), `Dockerfile` (6),
      `sshd_config` (6), юниты systemd (5)
- [x] Привязка каждого правила к мере ФСТЭК и к конкретному действующему
      приказу (поле `orders`)
- [x] Четыре формата вывода: `text`, `json`, `html`, `sarif` — последний
      для загрузки в GitHub Code Scanning, с реальными номерами строк и
      отпечатками находок (`partialFingerprints`), не зависящими от сдвига
      файла
- [x] Каталог правил `--list-rules` со сводкой покрытия групп мер ФСТЭК
- [x] Baseline (`--write-baseline` / `--baseline`) — внедрение в проект с
      существующим долгом без «красного CI с первого дня»
- [x] Порог провала сборки `--fail-on`, готовый GitHub Action
- [x] Два стенда для проверки инструмента: уязвимый и защищённый
- [x] Отключение правил тремя способами: комментарий `# fstec-lint: ignore`
      в проверяемом файле, флаги `--select` / `--ignore`, baseline
- [x] Разбор `Match`-блоков в `sshd_config` — директивы, переопределённые
      для отдельных хостов и пользователей, больше не пропускаются
- [x] Устойчивость к «грязному» дереву: битый или бинарный файл не роняет
      прогон (отдельный код выхода `3`), служебные каталоги вроде
      `node_modules` и `.git` пропускаются, остальное — через `--exclude`
- [x] CI: `ruff`, `ruff format`, `mypy`, `pytest` на Python 3.10–3.12
      и самосканирование обоих стендов; 244 теста, покрытие 95%
- [x] Границы разбора выписаны явно — [`docs/rules-subjects.md`](docs/rules-subjects.md),
      раздел «Что разбор не видит»: `Include` в `sshd_config`, `include`
      в `postgresql.conf`, `USER` внутри образа, подстановка переменных.
      Пустой отчёт не должен читаться как «проверено всё»

### Дальше

- [ ] Переустановить коды мер по методическому документу к приказу №117
      (см. «Статус кодов мер в правилах»). Блокирует всё остальное по
      нормативной части: перечень подмер и распределение по классам
      берутся из оригинала документа, не из обзоров. Вход для сопоставления
      готов — [`docs/rules-subjects.md`](docs/rules-subjects.md)
- [ ] Отдельно — привязка для ПДн после публикации приказа взамен №21
      (проект от 24.07.2026, см. «Правовой статус»; на 01.09.2026 приказ
      всё ещё не зарегистрирован в Минюсте)
- [ ] Класс ГИС / уровень защищённости ПДн как входной параметр и отчёт
      «требуемая мера → покрыта / нарушена / статикой не проверяется».
      Механика тут простая, а вот содержимое — нет: нужен выверенный
      базовый набор мер по классам К1–К3 (приказ №117) и по УЗ1–УЗ4
      (приказ №21 либо то, что придёт ему на смену), перенесённый из
      действующей редакции документа. Набор, набранный по памяти или
      «примерно», давал бы ложное «мера покрыта» в инструменте, которым
      готовятся к аттестации, — поэтому таблицы переносятся сверкой с
      текстом приказа, а не дописываются заодно с кодом
- [ ] Проверка `.env`-файлов на секреты в открытом виде — сейчас они
      ловятся только в секции `environment` внутри compose, сам `.env`
      не сканируется
- [ ] Раскрытие `Include` в `sshd_config` и `include`/`include_dir` в
      `postgresql.conf`: сейчас проверяется только переданный файл, а в
      дистрибутивах по умолчанию действующее значение директивы приходит
      из подключаемого — «нарушений не найдено» на таком конфиге
      означает меньше, чем выглядит (см. «Что разбор не видит»)

Вне области применения: группы мер, которые статический анализ конфигов
не может подтвердить в принципе (АВЗ, СОВ, ИНЦ и подобные) — им нужны
данные о работающей системе, а не о её конфигурации. `--list-rules`
показывает это явно, чтобы картина покрытия не выглядела полнее, чем есть.

## История изменений

Что менялось от версии к версии — в [`CHANGELOG.md`](CHANGELOG.md).
Записи для 0.1.0–0.8.0 восстановлены по истории коммитов: файл заведён
при подготовке 0.8.1.

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

**Measure codes are stale.** The codes in `rules/*.yaml` follow FSTEC
Order No. 17, which was repealed on 2026-03-01. Order No. 117 and its
accompanying methodology document changed both the composition and the
numbering of measures; the codes have not been reconciled. The `orders`
field currently records a historical mapping and is not a claim of
conformance with the requirements in force. What each rule actually
checks, stated without any regulatory claims, is in
[`docs/rules-subjects.md`](docs/rules-subjects.md).

**Disclaimer:** this tool helps you prepare for and self-check against
compliance requirements; it does not replace formal certification and is
not a certified security product. Rule-to-measure mappings are
indicative — verify them against the current edition of the order and
your own threat model before relying on them.

**Code quality:** every push runs `ruff check`, `ruff format --check`,
`mypy` and `pytest` (244 tests, 95% coverage) across Python
3.10–3.12, plus a self-scan of both example stacks as a pipeline smoke
test.

**Turning rules off:** `# fstec-lint: ignore C001, C009` as a comment in
the scanned file itself (it covers its own line and the next one, accepts
globs, and a bare `# fstec-lint: ignore` silences everything on that
line), `--ignore` / `--select` with rule ids or globs for a whole run, or
`--baseline` to accept existing debt and fail only on new findings.

**Exit codes:** `0` — clean, `1` — findings at or above `--fail-on`
(default `high`), `2` — usage error, `3` — some files could not be parsed
(a broken or binary file is reported and skipped, it never aborts the
scan). Vendor directories (`.git`, `node_modules`, `vendor`, `.venv`, …)
are always skipped; anything else via `--exclude GLOB`.

Quick start:

```bash
pip install "fstec-lint @ git+https://github.com/Desloft-debug/fstec-lint.git"
fstec-lint . --format html --output report.html --fail-on high
fstec-lint --list-rules   # rule catalogue + which FSTEC measure groups it covers

# adopting it in an existing project without a red CI on day one:
fstec-lint . --write-baseline .fstec-lint-baseline.json   # accept current debt
fstec-lint . --baseline .fstec-lint-baseline.json         # fail only on new findings
fstec-lint . --exclude "tests/fixtures/*"                 # skip your own noise
fstec-lint . --ignore C013 --select "C0*,D0*"             # narrow the rule set
```

See the table above (`Что проверяется`) for the full rule list, and
[`examples/`](examples) for a deliberately vulnerable stack next to its
hardened counterpart, with the exact `fstec-lint` output for both.
