from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

from . import __version__, history
from . import baseline as baseline_module
from .engine import (
    RulesError,
    ScanResult,
    discover_files,
    filter_by_uz,
    filter_rules,
    load_rules,
    scan,
    unknown_patterns,
)
from .models import Rule, Severity
from .output import visible, write_report
from .reporters import docx, html, json_reporter, passport, rules_catalog, sarif, text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fstec-lint",
        description=(
            "Статический аудит инфраструктуры (Docker Compose, Dockerfile, "
            "PostgreSQL, sshd_config, systemd). Меню: fstec-lint menu. Привязка к мерам "
            "защиты ФСТЭК (приказ №21 / приказ №117, заменивший №17)."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="каталог или файл для сканирования (по умолчанию: .)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "json-context", "html", "sarif", "passport", "docx"],
        default="text",
        help=("формат отчёта; passport — паспорта уязвимостей по ГОСТ Р 56545-2015 (приложение А)"),
    )
    parser.add_argument("-o", "--output", help="файл для сохранения отчёта (по умолчанию — stdout)")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="минимальная severity, при которой команда завершится с кодом 1 (по умолчанию: high)",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="показать каталог правил и покрытие групп мер ФСТЭК, ничего не сканируя",
    )
    parser.add_argument("--version", action="version", version=f"fstec-lint {__version__}")
    parser.add_argument(
        "--select",
        action="append",
        default=[],
        metavar="RULES",
        help=(
            "проверять только эти правила: id или glob через запятую "
            "(например C001,D0* ). Можно повторять"
        ),
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULES",
        help=(
            "не проверять эти правила: id или glob через запятую "
            "(например C009,C013). Применяется после --select"
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help=(
            "не сканировать файлы и каталоги, подходящие под glob "
            "(можно повторять). При обходе исключаются служебные каталоги вроде "
            ".git, node_modules и .venv; явно указанный файл не исключается"
        ),
    )
    parser.add_argument(
        "--production-only",
        action="store_true",
        help=(
            "пропустить вложенные каталоги test/tests, fixture/fixtures, "
            "example/examples, demo/demos"
        ),
    )
    parser.add_argument(
        "--uz",
        type=int,
        choices=[1, 2, 3, 4],
        metavar="LEVEL",
        help=(
            "проверять только правила из базового набора мер для уровня "
            "защищённости ПДн (приложение к приказу ФСТЭК №21): 1 — самый "
            "высокий. Остальные меры применяются при адаптации набора"
        ),
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="подавить совпадающие находки из baseline",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="записать текущие находки в baseline-файл; при ошибке сканирования код 3",
    )
    parser.add_argument(
        "--no-inline-suppressions",
        action="store_true",
        help="показывать все находки независимо от комментариев в исходниках",
    )
    parser.add_argument(
        "--strict-scope",
        action="store_true",
        help="считать прогон неполным при обнаруженных неразрешимых настройках",
    )
    parser.add_argument(
        "--require-input",
        action="store_true",
        help="считать прогон неполным без поддерживаемых файлов для выбранных правил",
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="Compose-файл внутри каталога проекта; повторите в порядке наложения",
    )
    parser.add_argument(
        "--gis-class",
        choices=["1", "2", "3"],
        help="заявленный класс ГИС для пояснений в json-context и SARIF, не фильтр проверок",
    )
    parser.add_argument("--history-db", type=Path, metavar="FILE", help="записать прогон в SQLite")
    parser.add_argument("--project", help="идентификатор проекта для истории")
    parser.add_argument("--revision", help="коммит или метка исходников для истории")
    parser.add_argument("--run-key", help="ключ повторной отправки одного прогона")
    return parser


def _rule_patterns(values: list[str]) -> list[str]:
    """--ignore C009,C013 --ignore D00* -> ['C009', 'C013', 'D00*']."""
    return [token.strip() for value in values for token in value.split(",") if token.strip()]


def _report_unknown(rules: list[Rule], patterns: list[str], option: str) -> bool:
    """Печатает нераспознанные шаблоны правил. True, если такие были.

    Опечатка в --select раньше давала «нарушений не найдено» и код 0:
    прогон, не проверивший ничего, выглядел как успешный аудит. Теперь
    это код 2 — ошибка вызова.
    """
    unknown = unknown_patterns(rules, patterns)
    for pattern in unknown:
        print(
            f"fstec-lint: {option} {visible(pattern)} — нет правил с таким id",
            file=sys.stderr,
        )
    return bool(unknown)


class UsageError(Exception):
    """Ошибка вызова: неверные аргументы или недоступный путь (код 2)."""


def _write(output: str, destination: str | None) -> None:
    """Пишет отчёт в файл или в stdout.

    Ошибка записи — это ошибка вызова (код 2), а не находка: раньше
    несуществующий каталог в --output давал трейсбек и код 1, то есть
    ровно тот же код, что «найдены нарушения выше порога».
    """
    if not destination:
        print(output)
        return
    try:
        write_report(Path(destination), (output + "\n").encode("utf-8"))
    except (OSError, ValueError, RuntimeError) as exc:
        raise UsageError(f"не удалось записать {destination}: {type(exc).__name__}") from None


def _run(argv: list[str] | None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["menu"] or (not argv and sys.stdin.isatty() and sys.stdout.isatty()):
        from .menu import run_menu

        return run_menu(lambda path: scan(path, inline_exceptions=False, strict_scope=True))
    if argv[:1] == ["history"]:
        return history.main(argv[1:])
    args = build_parser().parse_args(argv)
    if args.compose_file and args.list_rules:
        raise UsageError("--compose-file применим только к сканированию")
    if args.gis_class and (args.list_rules or args.format not in {"json-context", "sarif"}):
        raise UsageError("--gis-class предназначен для отчёта json-context или SARIF")
    if args.history_db is None:
        if any(v is not None for v in (args.project, args.revision, args.run_key)):
            raise UsageError("--project, --revision и --run-key требуют --history-db")
    elif not args.project or not args.revision or args.list_rules or args.write_baseline:
        raise UsageError("история требует --project и --revision в обычном сканировании")
    if args.history_db is not None:
        history.validate_db_path(
            args.history_db,
            [Path(value) for value in (args.path, args.output, args.baseline) if value],
        )

    select = _rule_patterns(args.select)
    ignore = _rule_patterns(args.ignore)
    all_rules = load_rules()
    unknown = _report_unknown(all_rules, select, "--select")
    unknown |= _report_unknown(all_rules, ignore, "--ignore")
    if unknown:
        return 2

    writes = [Path(value) for value in (args.output, args.write_baseline) if value]
    input_root = None if args.list_rules else Path(args.path)
    inputs = [path for path in (input_root, Path(args.baseline) if args.baseline else None) if path]
    overlay_inputs: list[Path] = []
    if input_root is not None and args.compose_file:
        if input_root.as_posix().startswith("//"):
            raise UsageError("для списка Compose нужен локальный каталог")
        for path in args.compose_file:
            if path.as_posix().startswith(("//", chr(92))) or (
                path.drive and not path.is_absolute()
            ):
                raise UsageError("для списка Compose нужны локальные пути")
            overlay_inputs.append(path if path.is_absolute() else input_root / path)
    for dest in writes:
        try:
            if input_root is not None and overlay_inputs:
                resolved_root = input_root.resolve()
                lexical_root = Path(os.path.abspath(input_root))
                for overlay in overlay_inputs:
                    lexical_file = Path(os.path.abspath(overlay))
                    if lexical_file.is_relative_to(lexical_root):
                        compare_file = resolved_root / lexical_file.relative_to(lexical_root)
                        if dest.resolve() == compare_file:
                            raise UsageError("отчёт не может перезаписать входной слой Compose")
            if (
                input_root is not None
                and input_root.is_dir()
                and dest.is_file()
                and dest.resolve().is_relative_to(input_root.resolve())
                and any(discover_files(dest).values())
            ):
                raise UsageError("отчёт или baseline не может перезаписать конфигурацию")
            if any(
                dest.resolve() == path.resolve()
                or (dest.is_file() and path.is_file() and dest.samefile(path))
                for path in inputs
            ):
                raise UsageError("отчёт или baseline не может перезаписать входной файл")
        except (OSError, RuntimeError):
            raise UsageError("не удалось проверить путь вывода") from None

    if args.list_rules:
        rules = filter_by_uz(filter_rules(all_rules, select, ignore), args.uz)
        if args.format in {"json", "json-context"}:
            _write(rules_catalog.render_json(rules), args.output)
        else:
            if args.format != "text":
                print(
                    f"fstec-lint: --list-rules не поддерживает формат {args.format}, "
                    "каталог выведен как text",
                    file=sys.stderr,
                )
            _write(rules_catalog.render_text(rules), args.output)
        return 0

    root = Path(args.path).absolute()
    if not root.exists():
        print(f"fstec-lint: путь не найден: {visible(root)}", file=sys.stderr)
        return 2

    if args.compose_file and not root.is_dir():
        raise UsageError("--compose-file требует указать каталог проекта")
    result = scan(
        root,
        exclude=args.exclude,
        select=select,
        ignore=ignore,
        uz=args.uz,
        production_only=args.production_only,
        record_checks=args.history_db is not None,
        inline_exceptions=not args.no_inline_suppressions,
        strict_scope=args.strict_scope,
        require_input=args.require_input,
        record_coverage=args.format == "json-context",
        compose_files=args.compose_file,
    )
    findings = result.findings

    for error in result.errors:
        print(f"fstec-lint: {visible(error.file)}: {visible(error.message)}", file=sys.stderr)

    if result.suppressed:
        print(
            f"fstec-lint: подавлено комментариями в файлах: {result.suppressed}",
            file=sys.stderr,
        )

    if args.write_baseline:
        _write(baseline_module.render(findings), args.write_baseline)
        print(
            f"fstec-lint: в baseline записано находок: {len(findings)} "
            f"({visible(args.write_baseline)})",
            file=sys.stderr,
        )
        if result.errors:
            print(
                f"fstec-lint: часть файлов не прочитана ({len(result.errors)}) — "
                "baseline записан по неполному прогону",
                file=sys.stderr,
            )
            return 3
        return 0

    if args.baseline:
        try:
            known = baseline_module.load(
                Path(args.baseline),
                findings=findings if not result.errors else None,
                scan_root=root.resolve().parent if root.is_file() else root.resolve(),
            )
        except baseline_module.BaselineError as exc:
            raise UsageError(str(exc)) from exc
        findings, suppressed = baseline_module.apply(findings, known)
        if suppressed:
            print(f"fstec-lint: подавлено baseline-ом: {suppressed}", file=sys.stderr)

    report_result = ScanResult(
        findings=findings,
        errors=result.errors,
        suppressed=result.suppressed,
        files_checked=result.files_checked,
        coverage=result.coverage,
        declared_gis_class="К" + args.gis_class if args.gis_class else None,
    )
    if args.format == "docx":
        if not args.output:
            raise UsageError("для формата docx требуется --output")
        applied = len(filter_by_uz(filter_rules(all_rules, select, ignore), args.uz))
        try:
            write_report(Path(args.output), docx.render(report_result, root.name, applied))
        except (OSError, ValueError, RuntimeError) as exc:
            raise UsageError(f"не удалось записать отчёт: {type(exc).__name__}") from None
        output = None
    elif args.format == "json":
        output = json_reporter.render(findings)
    elif args.format == "json-context":
        active = filter_by_uz(filter_rules(all_rules, select, ignore), args.uz)
        output = json_reporter.render(report_result, active_rules=active)
    elif args.format == "html":
        output = html.render(report_result, title=f"fstec-lint report — {root.name}")
    elif args.format == "sarif":
        output = sarif.render(report_result)
    elif args.format == "passport":
        output = passport.render(report_result)
    else:
        output = text.render(report_result)

    if output is not None:
        _write(output, args.output)

    if args.history_db is not None:
        active = filter_by_uz(filter_rules(all_rules, select, ignore), args.uz)
        profile = history.profile_digest(
            {
                "rules": sorted(rule.id for rule in active),
                "exclude": sorted(set(args.exclude)),
                "production_only": args.production_only,
                "single_file": root.is_file(),
                "strict_scope": args.strict_scope,
                "require_input": args.require_input,
                "compose_files": [
                    path.relative_to(root).as_posix()
                    if path.is_absolute() and path.is_relative_to(root)
                    else path.as_posix()
                    for path in args.compose_file
                ],
                "scanner_fingerprint": history.scanner_fingerprint(),
            }
        )
        try:
            run_id, inserted = history.record_scan(
                args.history_db,
                root,
                result,
                project=args.project,
                revision=args.revision,
                profile=profile,
                run_key=args.run_key,
            )
        except (OSError, RuntimeError, sqlite3.Error, UnicodeError) as exc:
            raise UsageError(f"история не записана ({type(exc).__name__})") from None
        operation = "записан" if inserted else "уже записан"
        print(f"fstec-lint: прогон истории {run_id} {operation}", file=sys.stderr)

    if result.errors:
        print(
            f"fstec-lint: файлов не удалось обработать: {len(result.errors)}",
            file=sys.stderr,
        )

    # Порог считается ПЕРЕД кодом 3. Код 3 отдельно от 1 нужен, чтобы
    # «инструмент не прочитал часть файлов» не путали с «нарушения
    # найдены», но приоритет у нарушения: прогон с одним битым файлом и
    # critical-находкой возвращал 3, и гейт, различающий эти коды, читал
    # его как чистый.
    if args.fail_on != "none":
        threshold = Severity.from_str(args.fail_on)
        if any(finding.rule.severity >= threshold for finding in findings):
            return 1

    return 3 if result.errors else 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except (UsageError, RulesError, history.HistoryError) as exc:
        print(f"fstec-lint: {visible(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
