# Разработка и проверки

Запускайте команды из корня рабочей копии с Python 3.10+. Для нового окружения:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]" -c constraints.txt
```

В Windows PowerShell: `py -3 -m venv .venv`, затем `.venv\Scripts\python.exe -m pip install -e ".[dev]" -c constraints.txt`. При исправной установленной `.venv` используйте её, не переустанавливая; проверка: `.venv/bin/python -m pip check` и импорт `fstec_lint.__file__` (в Windows используйте `.venv\Scripts\python.exe`).

Для Linux, из корня проекта:

```bash
.venv/bin/python -m pytest tests/ -v --cov=fstec_lint --cov-report=term-missing
.venv/bin/python -m ruff check fstec_lint tests
.venv/bin/python -m ruff format --check fstec_lint tests
.venv/bin/python -m mypy fstec_lint
.venv/bin/python -m fstec_lint examples/vulnerable-stack --fail-on none
.venv/bin/python -m fstec_lint examples/hardened-stack --fail-on high
.venv/bin/python -m fstec_lint examples/vulnerable-stack --fail-on high
.venv/bin/python -m pip_audit --strict -r constraints.txt
```

Последние три сканирования ожидают коды 0, 0 и 1 соответственно. `pip-audit` отдельно ставится в локальное окружение, если отсутствует; он не входит в `[dev]`. В Windows замените `.venv/bin/python` на `.venv\Scripts\python.exe`. `pytest` ограничен `tests/`, покрытие — `fstec_lint`, порог задан в `pyproject.toml`.

При необходимости `--basetemp` выбирайте новую уникальную подпапку внутри разрешённого временного каталога текущего запуска: pytest удаляет выбранный basetemp. Например, в PowerShell задайте `$runTemp` текущим разрешённым каталогом, затем `--basetemp (Join-Path $runTemp ("pytest-" + [guid]::NewGuid()))`. Не используйте существующую пользовательскую папку или старый Temp. Запуск может создать `.venv/`, `fstec_lint.egg-info/`, кэши Python, pytest, Ruff, Mypy и `.coverage`; это производные файлы. Служебные каталоги, эти производные и справочную копию `fstec-lint-1.1.0` исключают из manifest источников, сбора тестов и покрытия; реальные исходники исключать нельзя.

Для адресных регрессий запустите `.venv/bin/python -m pytest tests/test_output_privacy.py tests/test_input_boundaries.py tests/test_resource_limits.py`; в Windows используйте `.venv\Scripts\python.exe`. Бюджеты и переход HBA описаны в [security.md](security.md).

Проверки интеграционных замечаний: `.venv/bin/python -m pytest tests/test_product_acceptance.py -q`. Результат зависит от проверяемого снимка и не заменяет полный набор; актуальный локальный прогон указан в verification.md. Для Windows замените путь к интерпретатору на `.venv\Scripts\python.exe` и задайте новую уникальную папку `--basetemp` внутри разрешённого Temp.

Для проверки Include и открытых ограничений отдельно запускайте `python -m pytest tests/test_include_acceptance.py tests/future_feature_contracts.py`; второй файл содержит ещё не реализованные сценарии и не входит в обычный сбор `tests/`. Текущие результаты приведены в verification.md.

Граф YAML проверяется до построения объектов; нагрузочные регрессии выполняются в ограниченном процессе.

## Windows и Linux: кандидат разработки

В изолированном окружении используйте `python -m pip install -e ".[dev]" -c constraints.txt`, затем `python -m ruff check fstec_lint tests`, `python -m ruff format --check fstec_lint tests`, `python -m mypy fstec_lint`, `python -m pytest tests/ -v --cov=fstec_lint --cov-report=term-missing --cov-report=xml`. Результаты конкретного прогона см. в verification.md и отчётах проверок; они не устанавливаются самим наличием команд.
