"""Локальная демонстрация истории. Входы не исполняются."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    target = Path(sys.argv[1]).resolve()
    target.mkdir(parents=True)
    work = target / "inputs"
    work.mkdir()
    database = target / "history.sqlite3"
    results = {}

    def cli(name: str, expected: int, *args: str) -> None:
        command = [sys.executable, "-m", "fstec_lint", *args]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True,
            check=False,
        )
        (target / f"{name}.json").write_bytes(completed.stdout)
        (target / f"{name}.stderr.txt").write_bytes(completed.stderr)
        results[name] = completed.returncode
        if completed.returncode != expected:
            raise RuntimeError(f"{name}: ожидался код {expected}, получен {completed.returncode}")

    for revision, content, code in [
        ("A", b"FROM alpine:latest\n", 1),
        ("B", b"FROM alpine:3.23\n", 0),
        ("B-broken", b"\xff\xfe", 3),
    ]:
        case = work / revision
        case.mkdir()
        (case / "Dockerfile").write_bytes(content)
        cli(
            f"scan-{revision}",
            code,
            str(case),
            "--history-db",
            str(database),
            "--project",
            "sample",
            "--revision",
            revision,
            "--select",
            "D004",
            "--fail-on",
            "low",
            "-f",
            "json",
        )

    report = work / "unit.xml"
    report.write_text(
        '<testsuite name="unit" tests="1"><testcase classname="unit" name="test_tax" />'
        "</testsuite>",
        encoding="utf-8",
    )
    cli(
        "import-junit",
        0,
        "history",
        "import-junit",
        str(database),
        str(report),
        "--project",
        "sample",
        "--revision",
        "B-broken",
        "--runner-version",
        "fixture",
        "--profile",
        "unit",
    )
    cli("runs", 0, "history", "list", str(database), "--project", "sample")
    cli("delta-resolved", 0, "history", "diff", str(database), "1", "2")
    cli("delta-unknown", 0, "history", "diff", str(database), "1", "3")
    for name, expected in (("delta-resolved", "resolved"), ("delta-unknown", "unknown")):
        actual = json.loads((target / f"{name}.json").read_bytes())
        if len(actual) != 1 or actual[0]["change"] != expected:
            raise RuntimeError(f"{name}: неожиданное состояние")
    (target / "exit-codes.json").write_text(
        json.dumps(results, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
