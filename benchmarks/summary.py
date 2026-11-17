"""Сводка по результатам сверки: TP/FP/FN, точность и полнота."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def metric_values(tp: int, fp: int, fn: int) -> dict:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
    }


def metrics(tp: int, fp: int, fn: int) -> str:
    values = metric_values(tp, fp, fn)
    precision = "null" if values["precision"] is None else f"{values['precision']:.1%}"
    recall = "null" if values["recall"] is None else f"{values['recall']:.1%}"
    return f"TP={tp:<3} FP={fp:<3} FN={fn:<3} точность={precision} полнота={recall}"


def kics(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    print("KICS: agreement with fixture labels, not measured whole-project accuracy")
    print("  TP/FP/FN: service/file units; TN: negative files (do not combine)")
    print("  Eligible rule-id agreements after corpus exclusions (including ambiguous mappings).")
    if "evaluable_totals" in data:
        e = data["evaluable_totals"]
        print("  Evaluable mappings only:", metrics(e.get("tp", 0), e.get("fp", 0), e.get("fn", 0)))
        print(
            "  Excluded ambiguous queries:",
            e.get("unscorable_queries", 0),
            "; failed files:",
            e.get("scan_failed_files", 0),
        )
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
        valid = [r for r in rows if r.get(key) in {"tp", "fp", "fn", "tn"}]
        count = {o: sum(1 for r in valid if r[key] == o) for o in ("tp", "fp", "fn", "tn")}
        skipped = len(rows) - len(valid)
        note = f", вне матрицы: {skipped}" if skipped else ""
        line = metrics(count["tp"], count["fp"], count["fn"])
        print(f"  {oracle:22} {line} TN={count['tn']}{note}")
    main_only = [
        r
        for r in rows
        if r.get("class") != "directory" and r.get("sshd_outcome") in {"tp", "fp", "fn", "tn"}
    ]
    count = {o: sum(1 for r in main_only if r["sshd_outcome"] == o) for o in ("tp", "fp", "fn")}
    print(f"  {'sshd -T, без drop-in':22} {metrics(count['tp'], count['fp'], count['fn'])}")
    rest = [
        r for r in rows if r["rule"] != "S004" and r.get("sshd_outcome") in {"tp", "fp", "fn", "tn"}
    ]
    count = {o: sum(1 for r in rest if r["sshd_outcome"] == o) for o in ("tp", "fp", "fn")}
    print(f"  {'sshd -T, без S004':22} {metrics(count['tp'], count['fp'], count['fn'])}")


def linux(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["scenarios"]
    print("ComplianceAsCode: login.defs, pwquality.conf, default/useradd, rsyslog.conf")
    print("  Raw CaC label agreement; runtime is separate and may disagree.")
    runtime = [r for r in rows if r.get("runtime_outcome") in {"tp", "fp", "fn", "tn"}]
    if runtime:
        count = {o: sum(r["runtime_outcome"] == o for r in runtime) for o in ("tp", "fp", "fn")}
        print(
            "  pwquality runtime:",
            metrics(count["tp"], count["fp"], count["fn"]),
            "classified:",
            len(runtime),
        )
    for rule in sorted({r["rule"] for r in rows}):
        sub = [r for r in rows if r["rule"] == rule]
        count = {o: sum(1 for r in sub if r["outcome"] == o) for o in ("tp", "fp", "fn", "tn")}
        skipped = sum(1 for r in sub if r["outcome"] not in {"tp", "fp", "fn", "tn"})
        note = f", пропущено сценариев: {skipped}" if skipped else ""
        line = metrics(count["tp"], count["fp"], count["fn"])
        print(f"  {rule:6} {line} TN={count['tn']}{note}")


def main() -> None:
    results = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "historical/results"
    )
    kics(results / "kics.json")
    print()
    cac(results / "cac_sshd.json", "ComplianceAsCode: sshd, значения из сценариев")
    print()
    cac(results / "cac_sshd_insecure.json", "ComplianceAsCode: sshd, опасные значения")
    print()
    linux(results / "cac_linux.json")


if __name__ == "__main__":
    main()
