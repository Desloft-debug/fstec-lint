from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import baseline as baseline_module
from .engine import load_rules, scan
from .models import Severity
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


def _write(output: str, destination: str | None) -> None:
    if destination:
        Path(destination).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        rules = load_rules()
        if args.format == "json":
            _write(rules_catalog.render_json(rules), args.output)
        else:
            _write(rules_catalog.render_text(rules), args.output)
        return 0

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"fstec-lint: путь не найден: {root}", file=sys.stderr)
        return 2

    findings = scan(root)

    if args.write_baseline:
        Path(args.write_baseline).write_text(
            baseline_module.render(findings) + "\n", encoding="utf-8"
        )
        print(
            f"fstec-lint: в baseline записано находок: {len(findings)} ({args.write_baseline})",
            file=sys.stderr,
        )
        return 0

    if args.baseline:
        try:
            known = baseline_module.load(Path(args.baseline))
        except baseline_module.BaselineError as exc:
            print(f"fstec-lint: {exc}", file=sys.stderr)
            return 2
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

    if args.fail_on == "none":
        return 0

    threshold = Severity.from_str(args.fail_on)
    if any(finding.rule.severity >= threshold for finding in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
