# Проверки

Для локальной проверки используйте команды из [раздела разработки](development.md). Обязательны Ruff, Mypy, pytest с покрытием не ниже 90%, аудит зависимостей, проверка сборки и установки, а также CI на Linux с Python 3.10–3.12 и проверка Action на ревизии кандидата. Результаты конкретного запуска относятся только к проверенному снимку; hosted CI и независимая приёмка должны быть подтверждены перед выпуском.

## Проверка чтения файлов

Windows Python 3.12: адресная выборка `python -m pytest tests/ -q -p no:cacheprovider -k "handle_containment or postgresql_include or postgresql_boundaries or regressions or sshd_include or boundaries"` — 82 passed. Проверка `test_atomic_read_never_consumes_external_bytes` — 6 passed, 2 failed: в двух вариантах main имя `value.conf` не выбирается для PostgreSQL, а подмена срабатывает на контрольном чтении самого теста. Новый тест проверяет реальный основной анализ `postgresql.conf`. Ruff на двух изменённых исходниках и Mypy на `fstec_lint` прошли. Полный набор, Linux и независимая проверка этого кандидата не выполнялись; безопасность от всех гонок, Docker/HBA baseline и Compose merge остаются открытыми.

## Проверка предыдущего снимка и последующая интеграция

Для manifest `077839f14ba248e0531df0051b2399ed662a970cccce2158de91b8d1c310b071` QA на Windows Python 3.10 и 3.12 получил по 1548 passed и 19 failed; покрытие Python 3.10 составило 94,36%. Падения относятся к атомарности чтения, совместимости Docker baseline и миграции старых Docker/HBA записей. Эти результаты не являются проверкой последующего снимка. Linux, Windows Python 3.11, hosted Action и окончательная независимая приёмка не подтверждены.

При последующей интеграции адресная проверка Windows Python 3.10 командой `python -m pytest tests/test_product_acceptance.py tests/test_catalog_source_regressions.py -q` дала 169 passed и 16 failed: ошибки атомарного чтения и baseline сохраняются. Ruff и Mypy прошли. Это проверка разработчика, а не полный повтор QA; при необходимости `--basetemp` задаётся новой уникальной подпапкой разрешённого Temp. Manifest, команды и сборочные артефакты сохраняются отдельно в материалах соответствующей проверки.

## Проверка PostgreSQL Include

До исправления `tests/test_include_acceptance.py tests/future_feature_contracts.py` дали 27 passed и 9 failed. После исправлений адресный набор из семи файлов, включая тесты Include и PostgreSQL Include, дал 142 passed; отдельно `tests/future_feature_contracts.py` дал 5 passed и 2 failed (Compose merge и гонка TOCTOU). Ruff и Mypy на исходниках прошли. Эти проверки не заменяют полный pytest, security review или платформенную матрицу; результаты полного запуска и сборки сохраняются в служебных материалах запуска.

## Проверка границ Include

До исправлений `tests/test_postgresql_boundaries.py` дал 15 passed и 5 failed; после исправления — 20 passed. Общий результат и manifest финальной версии хранятся в материалах соответствующей проверки. Проверки предыдущих снимков не подтверждают окончательную версию; отдельные security, regulatory и hosted CI проверки остаются необходимыми.

## Промежуточная интеграционная проверка

Входной manifest: d6e96436bf706a01c56dc27b06366d5f9e4ce25cad6835e2229484ecf4505724. Промежуточный тест Windows Python 3.10: 187 passed, 20 failed; он выполнялся до последующих исправлений и не является финальной проверкой. Сборка, полный прогон итогового кандидата, security-аудит и независимая приёмка на текущий момент не подтверждены. Последующие результаты фиксируются в отчёте проверки без изменения этого файла.
