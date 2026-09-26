"""Сводка по результатам сверки: TP/FP/FN, точность и полнота."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def metrics(tp: int, fp: int, fn: int) -> str:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return f"TP={tp:<3} FP={fp:<3} FN={fn:<3} точность={precision:6.1%} полнота={recall:6.1%}"


def kics(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    print("KICS: Docker Compose и Dockerfile")
    for kind in ("full", "partial"):
        rows = [q for q in data["queries"] if q["match"] == kind]
        tp = sum(len(q["tp"]) for q in rows)
        fp = sum(len(q["fp"]) for q in rows)
        fn = sum(len(q["fn"]) for q in rows)
        label = "полное совпадение смысла" if kind == "full" else "частичное совпадение"
        print(f"  {label:26} ({len(rows):2} запросов)  {metrics(tp, fp, fn)}")
        disputed = [(q["query"], u, r) for q in rows for u, r in q.get("disputed", {}).items()]
        if disputed:
            fn_d = sum(1 for q in rows for u in q.get("disputed", {}) if u in q["fn"])
            fp_d = sum(1 for q in rows for u in q.get("disputed", {}) if u in q["fp"])
            line = metrics(tp, fp - fp_d, fn - fn_d)
            print(f"  {'  без спорных меток':26} ({len(disputed):2} исключено)  {line}")
            for query, unit, reason in disputed:
                print(f"      {query} / {unit}: {reason}")
    for q in data["queries"]:
        if q["fp"] or q["fn"]:
            print(f"    {q['rule']} ← {q['query']}: FN={q['fn']} FP={q['fp']}")


def cac(path: Path, title: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["scenarios"]
    print(title)
    for oracle, key in (("метка ComplianceAsCode", "outcome"), ("эталон sshd -T", "sshd_outcome")):
        valid = [r for r in rows if r[key] != "invalid"]
        count = {o: sum(1 for r in valid if r[key] == o) for o in ("tp", "fp", "fn", "tn")}
        skipped = len(rows) - len(valid)
        note = f", отвергнуто sshd: {skipped}" if skipped else ""
        line = metrics(count["tp"], count["fp"], count["fn"])
        print(f"  {oracle:22} {line} TN={count['tn']}{note}")
    main_only = [r for r in rows if r["class"] != "directory" and r["sshd_outcome"] != "invalid"]
    count = {o: sum(1 for r in main_only if r["sshd_outcome"] == o) for o in ("tp", "fp", "fn")}
    print(f"  {'sshd -T, без drop-in':22} {metrics(count['tp'], count['fp'], count['fn'])}")
    rest = [r for r in rows if r["rule"] != "S004" and r["sshd_outcome"] != "invalid"]
    count = {o: sum(1 for r in rest if r["sshd_outcome"] == o) for o in ("tp", "fp", "fn")}
    print(f"  {'sshd -T, без S004':22} {metrics(count['tp'], count['fp'], count['fn'])}")


def linux(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["scenarios"]
    print("ComplianceAsCode: login.defs, pwquality.conf, default/useradd, rsyslog.conf")
    for rule in sorted({r["rule"] for r in rows}):
        sub = [r for r in rows if r["rule"] == rule]
        count = {o: sum(1 for r in sub if r["outcome"] == o) for o in ("tp", "fp", "fn", "tn")}
        skipped = sum(1 for r in sub if r["outcome"] == "skipped")
        note = f", пропущено сценариев: {skipped}" if skipped else ""
        line = metrics(count["tp"], count["fp"], count["fn"])
        print(f"  {rule:6} {line} TN={count['tn']}{note}")


def main() -> None:
    results = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "results"
    kics(results / "kics.json")
    print()
    cac(results / "cac_sshd.json", "ComplianceAsCode: sshd, значения из сценариев")
    print()
    cac(results / "cac_sshd_insecure.json", "ComplianceAsCode: sshd, опасные значения")
    print()
    linux(results / "cac_linux.json")


if __name__ == "__main__":
    main()
