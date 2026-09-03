from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import baseline as baseline_module
from .engine import filter_rules, load_rules, scan, unknown_patterns
from .models import Rule, Severity
from .reporters import html, json_reporter, rules_catalog, sarif, text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fstec-lint",
        description=(
            "Статический аудит инфраструктуры (Docker Compose, Dockerfile, "
            "PostgreSQL, sshd_config, systemd) с привязкой находок к мерам "
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
        choices=["text", "json", "html", "sarif"],
        default="text",
        help="формат отчёта",
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
            "(можно повторять). Служебные каталоги вроде .git, node_modules "
            "и .venv исключены всегда"
        ),
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="не сообщать о находках, перечисленных в baseline-файле (падать только на новых)",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="записать текущие находки в baseline-файл и выйти с кодом 0",
    )
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
            f"fstec-lint: {option} {pattern} — нет правил с таким id",
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
        Path(destination).write_text(output + "\n", encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"не удалось записать {destination}: {exc.strerror or exc}") from exc


def _run(argv: list[str] | None) -> int:
    args = build_parser().parse_args(argv)

    select = _rule_patterns(args.select)
    ignore = _rule_patterns(args.ignore)
    all_rules = load_rules()
    unknown = _report_unknown(all_rules, select, "--select")
    unknown |= _report_unknown(all_rules, ignore, "--ignore")
    if unknown:
        return 2

    if args.list_rules:
        rules = filter_rules(all_rules, select, ignore)
        if args.format == "json":
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

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"fstec-lint: путь не найден: {root}", file=sys.stderr)
        return 2

    result = scan(root, exclude=args.exclude, select=select, ignore=ignore)
    findings = result.findings

    for error in result.errors:
        print(f"fstec-lint: {error.file}: {error.message}", file=sys.stderr)

    if result.suppressed:
        print(
            f"fstec-lint: подавлено комментариями в файлах: {result.suppressed}",
            file=sys.stderr,
        )

    if args.write_baseline:
        _write(baseline_module.render(findings), args.write_baseline)
        print(
            f"fstec-lint: в baseline записано находок: {len(findings)} ({args.write_baseline})",
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
            known = baseline_module.load(Path(args.baseline))
        except baseline_module.BaselineError as exc:
            raise UsageError(str(exc)) from exc
        findings, suppressed = baseline_module.apply(findings, known)
        if suppressed:
            print(f"fstec-lint: подавлено baseline-ом: {suppressed}", file=sys.stderr)

    if args.format == "json":
        output = json_reporter.render(findings)
    elif args.format == "html":
        output = html.render(findings, title=f"fstec-lint report — {root.name}")
    elif args.format == "sarif":
        output = sarif.render(findings)
    else:
        output = text.render(findings)

    _write(output, args.output)

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
    except UsageError as exc:
        print(f"fstec-lint: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
