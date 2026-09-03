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
(пункт приказа ФСТЭК N 117) → как исправить.

> **Важно.** Инструмент помогает готовиться к оценке соответствия и
> ускоряет самопроверку перед аттестацией, но не заменяет её и не
> является сертифицированным средством защиты информации. Соответствие
> находок конкретным пунктам приказов носит справочный характер —
> перед использованием в реальном проекте сверьте номера мер с
> действующей редакцией приказа/методического документа и вашей моделью
> угроз. См. раздел «Правовой статус» ниже — база сейчас в процессе
> замены.

## Правовой статус (на 03.09.2026)

Привязка правил ведётся по тексту действующего приказа, а не по обзорам.
Первоисточники, по которым она сверена, — приказ ФСТЭК России от
11.04.2025 N 117 (зарегистрирован Минюстом России 16.06.2025, N 82619).

- **Приказ N 17** (защита ГИС) **утратил силу**. Его заменил
  **приказ ФСТЭК России N 117** от 11.04.2025, действующий
  **с 1 марта 2026 года**. Аттестаты, выданные до этой даты, остаются
  действительными (пункт 3 приказа).
- **Приказ N 21** (защита ПДн) формально ещё действует. Опубликован
  проект приказа о его отмене с переходом на модель самостоятельного
  выбора мер оператором; на дату в заголовке раздела приказ не
  зарегистрирован в Минюсте. До регистрации ссылки на N 21 в поле
  `orders` сохраняются.

### Как устроены меры в приказе N 117

Это главное отличие от прежней базы, и оно меняет то, как инструмент
привязывает находки.

**Таблицы кодов мер больше нет.** Коды вида `ЗСВ.2`, `УПД.4`, `ИАФ.1`
жили в приложении к приказу N 17 и утратили силу вместе с ним. В приказе
N 117 таких кодов **нет вообще**. Вместо фиксированного базового набора
Требования задают два перечня:

- **пункт 34** — 22 мероприятия по защите информации (подпункты а–х):
  контроль конфигураций, управление уязвимостями и обновлениями,
  привилегированный и удалённый доступ, мониторинг ИБ, разработка
  безопасного ПО, непрерывность функционирования, защита при
  использовании искусственного интеллекта и другие;
- **пункт 63** — 17 базовых мер защиты (подпункты а–с). Среди них
  впервые выделены отдельными мерами **защита технологий контейнерных
  сред и их оркестрации** (п. 63 д)), защита виртуализации и облачных
  вычислений (п. 63 г)), защита программных интерфейсов взаимодействия
  приложений (п. 63 з)) и защита технологий интернета вещей (п. 63 л)).

Базовые меры адаптируются под архитектуру системы, верифицируются по
актуальным угрозам, дополняются и усиливаются (пункт 62). Требуемая
стойкость задаётся не набором галочек, а уровнем возможностей
нарушителя: К3 — базовый, К2 — повышенный, К1 — высокий (пункт 64).

**Оценка состояния защиты — через два показателя** (пункт 31):
показатель защищённости **Кзи** (пересчёт не реже раза в полгода) и
показатель уровня зрелости **Пзи** (не реже раза в два года). Значения,
не соответствующие нормированным, направляются во ФСТЭК. Методики
расчёта заданы Методикой оценки ФСТЭК России от 11.11.2025 —
см. [`docs/kzi.md`](docs/kzi.md).

### Что это значит для fstec-lint

Инструмент **не является средством защиты информации**. В терминах
приказа N 117 это поддержка двух мероприятий оператора:

- **п. 34 б)** — контроль конфигураций информационных систем;
- **п. 34 ф)** — проведение контроля уровня защищённости информации.

Находки — подтверждающий материал для оценки показателя защищённости
**Кзи**, но не сам показатель. Методика оценки (утв. ФСТЭК России
11.11.2025) в пункте 20 и) прямо называет исходными данными «результаты
работы инструментальных средств оценки (анализа) защищённости», а
приложение № 1 требует для показателя `k32` отчёт средства анализа
защищённости, для `k31` — перечень интерфейсов, доступных из Интернета.

Из шестнадцати частных показателей Кзи инструмент даёт материал по
четырём: `k23`, `k31`, `k32`, `k42`. Их суммарный вклад в Кзи —
**0,3125 из 1,0**. Остальное закрывают организационные документы,
учётные записи, антивирусная защита, почта и мониторинг. Разбор с
формулой и шкалой — в [`docs/kzi.md`](docs/kzi.md).

Правило C011 (незащищённый Docker Engine API) привязано к **п. 63 з)**,
правила про сам контейнер — к **п. 63 д)**. Это прямое попадание в
предмет: до N 117 отдельной меры под контейнерные среды не было, и
привязывать такие находки приходилось к общей «защите среды
виртуализации».

Полная матрица «правило → пункт приказа», обратная таблица и перечень
непокрываемых мер — в [`docs/measures-117.md`](docs/measures-117.md).
Место инструмента в оценке показателя защищённости Кзи, включая честную
оценку его вклада — в [`docs/kzi.md`](docs/kzi.md).
Привязка проверяется тестами: правило не может сослаться на
несуществующий подпункт или разойтись с формулировкой приказа
(`tests/test_rules_integrity.py`).

### Три уровня привязки

Методический документ ФСТЭК России от 12.04.2026 «Состав и содержание
мероприятий и мер по защите информации, содержащейся в информационных
системах» детализирует приказ до подмер. Он задаёт две таксономии:
19 мероприятий (раздел III) и 17 групп мер, разбитых на 95 подмер
(раздел IV). Каждое правило привязано к обеим:

| Уровень | Пример | Что это |
|---|---|---|
| Мера приказа | `п. 63 д)` | Защита технологий контейнерных сред и их оркестрации |
| Подмера методички | `ЗКО.5` | Изоляция контейнеров в контейнерной среде |
| Мероприятие методички | `ПД` | Защита информации при предоставлении привилегированного доступа |

Группа **ЗКО** («Защита технологий контейнерных сред и их оркестрации»,
8 подмер) появилась именно в методическом документе 2026 года. До него
находки про контейнеры привязывались к защите среды виртуализации
`ЗСВ` — этот код и стоит в `legacy_measure` большинства правил Compose.

Предмет группы `ЗКО` задан не приказом и не методичкой, а
**ГОСТ Р 70860-2023** «Информационные технологии. Облачные вычисления.
Общие технологии и методы»: приказ определяет меру п. 63 д) ссылкой на
пункт 3.10 этого стандарта. Термины ГОСТа («контейнерная служба»,
«реестр контейнеров», «оркестрация») используются в формулировках
правил — инструмент, называющий объекты иначе, чем документ, по
которому его проверяют, читается как написанный по мотивам.

Каждая ссылка проверяется тестами: правило не может сослаться на
несуществующую подмеру, разойтись с формулировкой документа или указать
неописанный пункт ГОСТа. Полные
таблицы — в [`docs/measures-117.md`](docs/measures-117.md).

### Историческая привязка

Коды приказа N 17 сохранены в поле `legacy_measure` каждого правила —
чтобы миграция была прослеживаемой, а не выглядела как переписывание
истории. В отчётах они выводятся в JSON и в каталоге правил, но не
используются как утверждение о соответствии.

Ссылки ниже — обзоры, а не источник данных для правил: ни одно значение
в `rules/*.yaml` по ним не проставляется.

Источники: [CISOClub о новом приказе ФСТЭК взамен №21](https://cisoclub.ru/fstjek-rossii-gotovit-otmenu-prikaza-21-i-novuju-sistemu-zashhity-personalnyh-dannyh/), [обзор приказа №117 (Angara Security)](https://www.angarasecurity.ru/stati/analiz-prikaza-fstek-rossii-117/), [BI.ZONE о группах мер приказа №117](https://bi.zone/expertise/insights/prikaz-fstek-rossii-117-novyy-etap-zashchity-informatsii-v-gossektore/).

---

## Что проверяется

**Docker Compose** (`docker-compose.yml` / `compose.yaml`):

| Правило | Проблема | Приказ N 117 |
|---|---|---|
| C001 | Контейнер без `user:` либо с `user: root` — работает от root | п. 63 б) |
| C002 | `privileged: true` | п. 63 д) |
| C003 | Опасные `cap_add` (`SYS_ADMIN`, `NET_ADMIN`, `ALL`...) | п. 63 д) |
| C004 | Пароль/токен в `environment` открытым текстом или как дефолт `${VAR:-...}` | п. 63 а) |
| C005 | Порт СУБД опубликован на все интерфейсы | п. 63 п) |
| C006 | Образ без версии или digest (`:latest`) | п. 34 г) |
| C007 | `network_mode: host` | п. 63 п) |
| C008 | Смонтирован `docker.sock` | п. 63 д) |
| C009 | Файловая система контейнера не `read_only` | п. 63 д) |
| C010 | Нет `no-new-privileges:true` | п. 63 б) |
| C011 | Docker Engine API (порт 2375/2376) опубликован наружу | п. 63 з) |
| C012 | Нет ограничений ресурсов (mem_limit/cpus/deploy.resources.limits) | п. 63 р) |
| C013 | Нет `healthcheck` | п. 34 о) |
| C014 | Включён debug-режим (`*DEBUG=true`) | п. 34 б) |
| C015 | Смонтирован чувствительный путь хоста (`/`, `/etc`, `/proc`...) | п. 63 д) |

**PostgreSQL** (`postgresql.conf` / `pg_hba.conf`):

| Правило | Проблема | Приказ N 117 |
|---|---|---|
| P001 | `trust`/`md5` в `pg_hba.conf` | п. 63 а) |
| P002 | Подключение разрешено с `0.0.0.0/0` | п. 63 п) |
| P003 | `listen_addresses = '*'` | п. 63 п) |
| P004 | Логирование подключений выключено | п. 63 в) |
| P005 | `ssl = off` | п. 63 с) |
| P006 | `password_encryption = md5` | п. 63 а) |
| P007 | `log_statement` не `ddl`/`mod`/`all` | п. 63 в) |
| P008 | Не задан `statement_timeout` | п. 63 р) |

**SSH** (`sshd_config`):

| Правило | Проблема | Приказ N 117 |
|---|---|---|
| S001 | `PermitRootLogin yes`/`without-password` | п. 34 к) |
| S002 | `PasswordAuthentication yes` | п. 34 з) |
| S003 | `PermitEmptyPasswords yes` | п. 63 а) |
| S004 | Включён устаревший `Protocol 1` | п. 63 с) |
| S005 | `X11Forwarding yes` | п. 34 з) |
| S006 | `MaxAuthTries` больше 4 | п. 63 а) |

Условные блоки `Match` разбираются наравне с глобальной секцией: если
`PermitRootLogin no` стоит вверху файла, а внутри `Match Address
10.0.0.0/8` он снова `yes` — это находка, и в отчёте видно, в каком
именно блоке. Директива, не заданная внутри блока, наследуется сверху и
повторно не считается, поэтому одна и та же проблема не размножается по
числу блоков.

**systemd** (`*.service`, секция `[Service]`):

| Правило | Проблема | Приказ N 117 |
|---|---|---|
| U001 | Сервис выполняется от root (`User` не задан, `DynamicUser` выключен) | п. 63 б) |
| U002 | Нет `NoNewPrivileges=true` (`yes`/`on`/`1` равнозначны) | п. 63 б) |
| U003 | Нет `ProtectSystem=yes`/`full`/`strict` | п. 63 б) |
| U004 | Нет `PrivateTmp=true` (`yes`/`on`/`1` равнозначны) | п. 63 б) |
| U005 | Нет `ProtectHome=true`/`read-only`/`tmpfs` | п. 63 б) |

**Dockerfile** (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`):

| Правило | Проблема | Приказ N 117 |
|---|---|---|
| D001 | В финальном стейдже нет `USER` либо это `USER root` | п. 63 б) |
| D002 | `ADD` загружает файл по URL без проверки | п. 34 г) |
| D003 | Секрет передан через `ARG` | п. 63 а) |
| D004 | Базовый образ (`FROM`) не закреплён по версии | п. 34 г) |
| D005 | `curl`/`wget` передаётся напрямую в shell (`\|` в `RUN`) | п. 34 м) |
| D006 | Не задан `HEALTHCHECK` | п. 34 о) |

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

### Паспорта уязвимостей

`--format passport` выводит находки в форме паспорта уязвимости по
**ГОСТ Р 56545-2015** «Защита информации. Уязвимости информационных
систем. Правила описания уязвимостей», приложение А:

```bash
fstec-lint . --format passport --output passports.txt
```

Заполняются все элементы, обязательные по пунктам 5.1.2 и 5.1.3
стандарта, включая идентификатор типа недостатка (CWE) и способ
(правило) обнаружения уязвимости — пункт 5.2.16 требует формализованное
правило, и у линтера оно есть по построению. Степени опасности совпадают
с четырьмя значениями пункта 5.2.18 один в один.

Элементы, которые статический анализ определить не может (версия ПО,
аппаратная платформа, вектор CVSS), помечаются явно, а не выдумываются.
Подробно — в [`docs/passport.md`](docs/passport.md).

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
  [HIGH] C001  п. 63 б)               Контейнер запускается от имени root
  [CRIT] C002  п. 63 д)               Контейнер запущен в privileged-режиме
  ...

Затронутые пункты приказа ФСТЭК N 117: п. 34 б) (1), п. 34 г) (3), п. 34
 з) (2), п. 34 к) (1), п. 34 м) (1), п. 34 о) (2), п. 63 а) (6), п. 63 б
) (8), п. 63 в) (2), п. 63 д) (5), п. 63 з) (1), п. 63 п) (4), п. 63 р) 
(2), п. 63 с) (2)
```

Сводка внизу честно показывает и обратное — какие пункты приказа
инструмент **не** закрывает: из 17 базовых мер пункта 63 статическим
анализом конфигураций затрагиваются восемь. Антивирусная защита,
обнаружение вторжений, защита конечных и мобильных устройств и прочее
требуют данных о работающей системе, а не о её конфигурации. Полный
разбор — в [`docs/measures-117.md`](docs/measures-117.md).

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
       мера: п. 63 д) — Защита технологий контейнерных сред и их оркестрации
       факт: сервис запущен с privileged: true
       фикс: Уберите privileged: true. Если приложению нужны отдельные
             привилегии — выдайте только необходимые capabilities через cap_add.

[CRIT] C004 Секрет в открытом виде в environment
       файл: examples/vulnerable-stack/docker-compose.yml
       где:  service:db
       мера: п. 63 а) — Идентификация и аутентификация
       факт: переменная POSTGRES_PASSWORD содержит секрет в открытом виде
       фикс: Используйте docker secrets, внешний секрет-менеджер либо
             .env-файл, исключённый из системы контроля версий.

[CRIT] P001 Слабый или отсутствующий метод аутентификации в pg_hba.conf
       файл: examples/vulnerable-stack/pg_hba.conf
       где:  pg_hba: local   all       all                trust
       мера: п. 63 а) — Идентификация и аутентификация
       факт: метод аутентификации 'trust' разрешает подключение без пароля
       фикс: Используйте scram-sha-256 для всех записей pg_hba.conf.

[CRIT] C011 Незащищённый Docker Engine API опубликован наружу
       файл: examples/vulnerable-stack/docker-compose.yml
       где:  service:web
       мера: п. 63 з) — Защита программных интерфейсов взаимодействия приложений
       приказ: Приказ ФСТЭК №117 от 11.04.2025 (ГИС, действует с 01.03.2026,
               заменил №17). Для ИСПДн — приказ №21 до его замены
       факт: порт 2375:2375 — доступ к нему эквивалентен root на хосте
       фикс: Не публикуйте сокет Docker наружу; используйте TLS (--tlsverify).

[HIGH] S001 Разрешён вход root по SSH
       файл: examples/vulnerable-stack/sshd_config
       где:  sshd_config: PermitRootLogin
       мера: п. 34 к) — Обеспечение защиты информации при предоставлении
             привилегированного доступа
       факт: PermitRootLogin yes — вход root по SSH разрешён
       фикс: Установите PermitRootLogin no, используйте sudo от именного аккаунта.

[HIGH] U001 Сервис выполняется от root
       файл: examples/vulnerable-stack/app.service
       где:  [Service]: User
       мера: п. 63 б) — Управление доступом
       факт: User не задан или равен root — процесс выполняется от root
       фикс: Заведите отдельного системного пользователя (User=<имя>).

[CRIT] D005 curl/wget передаётся напрямую в shell
       файл: examples/vulnerable-stack/Dockerfile:6
       где:  stage 1: RUN curl -sSL https://get.example.com/install.sh | bash
       мера: п. 34 м) — Обеспечение разработки безопасного программного обеспечения
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
- [x] Привязка мер переустановлена по тексту приказа №117: каждое правило
      ссылается на конкретный подпункт пункта 34 или 63, перечни выписаны
      в `fstec_lint/measures.py`, матрица трассировки —
      [`docs/measures-117.md`](docs/measures-117.md). Тесты не дают
      сослаться на несуществующий подпункт или разойтись с формулировкой
      приказа; коды утратившего силу №17 сохранены в `legacy_measure`

### Дальше

- [x] Детализация до подмер по методическому документу ФСТЭК от
      12.04.2026: каждое правило ссылается на подмеру раздела IV и на
      мероприятие раздела III, обе ссылки проверяются тестами
- [ ] Методика оценки показателя уровня зрелости Пзи (пункт 31 б)
      Требований). Методика Кзи от 11.11.2025 разобрана — см.
      [`docs/kzi.md`](docs/kzi.md), Пзи пока нет
- [ ] Привязка для ПДн после публикации приказа взамен №21 (проект
      опубликован, в Минюсте не зарегистрирован — см. «Правовой статус»)
- [ ] Класс защищённости К1–К3 как входной параметр. В приказе №117
      фиксированного базового набора по классам больше нет: пункт 64
      задаёт не перечень мер, а уровень возможностей нарушителя, от
      которого меры обязаны защищать (К3 — базовый, К2 — повышенный,
      К1 — высокий). Соответствие «уровень возможностей → строгость
      правила» берётся из методических документов, а не придумывается
- [ ] Проверка `.env`-файлов на секреты в открытом виде — сейчас они
      ловятся только в секции `environment` внутри compose, сам `.env`
      не сканируется
- [ ] Раскрытие `Include` в `sshd_config` и `include`/`include_dir` в
      `postgresql.conf`: сейчас проверяется только переданный файл, а в
      дистрибутивах по умолчанию действующее значение директивы приходит
      из подключаемого — «нарушений не найдено» на таком конфиге
      означает меньше, чем выглядит (см. «Что разбор не видит»)

Вне области применения: меры, которые статический анализ конфигураций
не может подтвердить в принципе (антивирусная защита, обнаружение
вторжений, защита конечных и мобильных устройств) — им нужны
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
its **40 rules** to a specific clause of FSTEC Order No. 117 (state
information systems) and, where applicable, Order No. 21 (personal data).

Existing scanners (Docker Bench, Lynis, Trivy, Checkov) map findings to
CIS Benchmarks or NIST controls. Nothing maps a misconfiguration directly
onto a specific FSTEC requirement, which is exactly what a compliance
engineer needs before certification. `fstec-lint` fills that gap:
finding → the specific clause of FSTEC Order No. 117 → concrete remediation.

**Regulatory status (as of 2026-09-03):** Order No. 17 (state information
systems) has been **repealed** and replaced by **Order No. 117** of
2025-04-11 (registered with the Ministry of Justice on 2025-06-16, reg.
No. 82619), in force since 2026-03-01. Order No. 21 (personal data) is
technically still in force; a draft order repealing it has been
published but, as of this writing, is not yet registered.

**There are no measure codes in Order No. 117.** Codes such as `ЗСВ.2`
or `УПД.4` lived in the appendix to Order No. 17 and were repealed with
it. Instead, the requirements define two lists: **clause 34** — 22
information-protection activities (items а–х), and **clause 63** — 17
baseline protection measures (items а–с). Notably, clause 63 introduces
**protection of container environments and their orchestration**
(63 д)) and **protection of application programming interfaces**
(63 з)) as measures in their own right — neither existed under Order
No. 17. Required strength is expressed as the intruder capability level
the measures must withstand (clause 64): basic for class К3, elevated
for К2, high for К1.

Every rule cites the exact clause it maps to, verified against the text
of the order by `tests/test_rules_integrity.py`: a rule cannot reference
a non-existent item or drift from the order's wording. The old Order
No. 17 codes are preserved in a `legacy_measure` field for traceability,
not as a conformance claim. Full mapping matrix, reverse table, and the
list of measures the tool does **not** cover:
[`docs/measures-117.md`](docs/measures-117.md).

**What this tool is, in the order's own terms:** not a security product,
but support for two operator activities — clause 34 б) (configuration
control of information systems) and clause 34 ф) (assessing the level of
information protection). Findings feed the Кзи protection indicator
defined in clause 31; they are not the indicator itself, whose
normative values come from FSTEC methodology documents.

**Disclaimer:** this tool helps you prepare for and self-check against
compliance requirements; it does not replace formal certification and is
not a certified security product. Rule-to-measure mappings are
indicative — verify them against the current edition of the order and
your own threat model before relying on them.

**Code quality:** every push runs `ruff check`, `ruff format --check`,
`mypy` and `pytest` (250 tests, 95% coverage) across Python
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
