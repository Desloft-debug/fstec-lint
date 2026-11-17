"""Сверка fstec-lint с размеченными примерами KICS (Docker Compose и Dockerfile).

У каждого запроса KICS есть файлы positive*/negative* и
positive_expected_result.json со строками, где запрос обязан сработать.
Для запросов, совпадающих по смыслу с правилами fstec-lint, считается:

    TP — KICS ожидает срабатывание, fstec-lint его дал;
    FN — KICS ожидает срабатывание, fstec-lint промолчал;
    FP — fstec-lint сработал там, где KICS срабатывания не ожидает;
    TN — успешно проверенный negative-файл, где оба молчат.

Для Compose единица сравнения — сервис (строка KICS переводится в
сервис, внутри которого она стоит), для Dockerfile — файл.

Запуск:
    git clone https://github.com/Checkmarx/kics.git
    python benchmarks/kics_eval.py path/to/kics > benchmarks/results/kics.json
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import yaml

from fstec_lint.engine import scan

# Сопоставление зафиксировано до прогона. «partial» — смысл пересекается
# не полностью, расхождения по таким парам разбираются отдельно.
MAPPING = {
    "dockerCompose": {
        "privileged_containers_enabled": ("C002", "full"),
        "container_capabilities_unrestricted": ("C003", "partial"),
        "docker_socket_mounted_in_container": ("C008", "full"),
        "healthcheck_not_set": ("C013", "full"),
        "memory_not_limited": ("C012", "partial"),
        "cpus_not_limited": ("C012", "partial"),
        "no_new_privileges_not_set": ("C010", "full"),
        "shared_host_network_namespace": ("C007", "full"),
        "volume_has_sensitive_host_directory": ("C015", "partial"),
    },
    "dockerfile": {
        "missing_user_instruction": ("D001", "full"),
        "last_user_is_root": ("D001", "full"),
        "healthcheck_instruction_missing": ("D006", "full"),
        "image_version_not_explicit": ("D004", "full"),
        "image_version_using_latest": ("D004", "full"),
        "curl_or_wget_instead_of_add": ("D002", "full"),
    },
}

# Метки KICS, которые противоречат семантике Docker Compose. Метрики
# печатаются и с ними, и без них; причина указана для каждой.
DISPUTED = {
    ("volume_has_sensitive_host_directory", "positive1.yaml:backup"): (
        "'- /var/lib/backup/data' — анонимный том с путём внутри контейнера, "
        "каталог хоста не монтируется"
    ),
}

# C012 reports a combined CPU/memory failure without a stable parameter subtype.
# Rule-id agreement is retained for reproducibility, but is not evidence that
# the particular KICS query was detected. Never infer subtype from translated text.
AMBIGUOUS = {
    "memory_not_limited": "C012 has no machine-readable memory/CPU finding subtype",
    "cpus_not_limited": "C012 has no machine-readable memory/CPU finding subtype",
}
POLICY_NOTES = {
    "volume_has_sensitive_host_directory": (
        "C015 sensitive host paths and mount semantics differ from KICS; "
        "raw labels are unchanged, not proof of identical policy coverage"
    ),
}
METRIC_UNITS = {
    "tp_fn_fp": "query-qualified Compose service (filename fallback) or Dockerfile file",
    "tn_files": "successfully scanned negative fixture files",
    "samples": "fixture executions, not unique production configurations",
    "accuracy": None,
    "accuracy_reason": "TN files and TP/FN/FP finding units cannot be combined",
}

TARGET_NAME = {"dockerCompose": "docker-compose.yml", "dockerfile": "Dockerfile"}


def service_at(text: str, line: int) -> str | None:
    """Имя сервиса Compose, внутри которого стоит строка line (с 1)."""
    root = yaml.compose(text)
    if not isinstance(root, yaml.MappingNode):
        return None
    for key, value in root.value:
        if key.value != "services" or not isinstance(value, yaml.MappingNode):
            continue
        # A line-only label cannot distinguish two inline service keys.
        if sum(skey.start_mark.line + 1 == line for skey, _ in value.value) > 1:
            return None
        for index, (skey, _) in enumerate(value.value):
            start = skey.start_mark.line + 1
            # Alias values reuse the anchor node and its old source marks.
            # Service ownership therefore follows keys, never value-node marks.
            if index + 1 < len(value.value):
                end = value.value[index + 1][0].start_mark.line + 1
                end_line_has_value = False
            else:
                end = value.end_mark.line + 1
                # Mapping end is exclusive; inline values and EOF without a
                # newline still occupy the end line, a following root key does not.
                end_line_has_value = value.end_mark.column > skey.start_mark.column
            if start <= line and (line < end or (line == end and end_line_has_value)):
                return str(skey.value)
    return None


def run_one(platform: str, sample: Path) -> tuple[list[dict], list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / TARGET_NAME[platform]
        shutil.copy(sample, target)
        result = scan(Path(tmp))
        findings = [
            {"rule": f.rule.id, "location": f.location, "line": f.line} for f in result.findings
        ]
        errors = [str(e) for e in result.errors]
        return findings, errors


def unit(platform: str, sample: Path, finding_location: str | None, line: int | None) -> str:
    if platform == "dockerfile":
        return sample.name
    if finding_location and finding_location.startswith("service:"):
        return f"{sample.name}:{finding_location.split(':', 1)[1].split(' ')[0]}"
    if line is not None:
        service = service_at(sample.read_text(encoding="utf-8"), line)
        if service:
            return f"{sample.name}:{service}"
    return sample.name


def evaluate(kics: Path) -> dict:
    report: dict = {
        "schema_version": 2,
        "metrics_basis": (
            "eligible rule-id agreement after corpus exclusions; use evaluable for scored cases"
        ),
        "metric_units": METRIC_UNITS,
        "queries": [],
        "totals": defaultdict(int),
        "evaluable_totals": defaultdict(int),
    }
    for platform, queries in MAPPING.items():
        for query, (rule, kind) in queries.items():
            test_dir = kics / "assets" / "queries" / platform / query / "test"
            expected_raw = json.loads((test_dir / "positive_expected_result.json").read_text())
            samples = sorted(
                p
                for p in test_dir.iterdir()
                if p.name.startswith(("positive", "negative"))
                and p.suffix in (".yaml", ".yml", ".dockerfile", "")
                and p.is_file()
                and not p.name.endswith(".json")
            )
            expected = set()
            positives = [s for s in samples if s.name.startswith("positive")]
            corpus_errors = []
            unresolved_samples = set()
            sample_by_name = {sample.name: sample for sample in samples}
            for item in expected_raw:
                name = item.get("filename") or item.get("fileName")
                if name is None and len(positives) == 1:
                    name = positives[0].name
                if not isinstance(name, str) or name not in sample_by_name:
                    corpus_errors.append(
                        {
                            "sample": name,
                            "line": item.get("line"),
                            "scoring_status": "unscorable",
                            "reason": "expected fixture is not in discovered scan inputs",
                        }
                    )
                    continue
                sample = sample_by_name[name]
                expected_unit = unit(platform, sample, None, item["line"])
                if platform == "dockerCompose" and expected_unit == sample.name:
                    unresolved_samples.add(sample.name)
                    corpus_errors.append(
                        {
                            "sample": sample.name,
                            "line": item["line"],
                            "scoring_status": "unscorable",
                            "reason": "expected line cannot be resolved to one Compose service",
                        }
                    )
                    continue
                expected.add(expected_unit)
            expected = {u for u in expected if u.split(":", 1)[0] not in unresolved_samples}
            got = set()
            errors = {}
            sample_rows = []
            for sample in samples:
                try:
                    findings, errs = run_one(platform, sample)
                except Exception as exc:
                    findings, errs = [], [f"{type(exc).__name__}: {exc}"]
                if errs:
                    errors[sample.name] = errs
                sample_rows.append(
                    {
                        "sample": sample.name,
                        "scan_status": "failed" if errs else "completed",
                        "scan_errors": errs,
                        "raw_findings": findings,
                        "scoring_status": "scan_failed"
                        if errs
                        else (
                            "unscorable"
                            if query in AMBIGUOUS or sample.name in unresolved_samples
                            else "evaluable"
                        ),
                        "reason": (
                            "unresolved Compose expected line; whole fixture excluded"
                            if sample.name in unresolved_samples
                            else AMBIGUOUS.get(query)
                        ),
                    }
                )
                for f in findings:
                    if f["rule"] == rule and sample.name not in unresolved_samples:
                        got.add(unit(platform, sample, f["location"], f["line"]))
            negatives = [s.name for s in samples if s.name.startswith("negative")]
            clean_negatives = [
                n
                for n in negatives
                if n not in errors
                and n not in unresolved_samples
                and not any(u == n or u.startswith(n + ":") for u in got)
            ]
            tp, fn, fp = expected & got, expected - got, got - expected
            # Failed scans are not valid negative predictions. Preserve raw
            # agreement separately, and exclude all units from failed fixtures.
            valid_expected = {u for u in expected if u.split(":", 1)[0] not in errors}
            valid_got = {u for u in got if u.split(":", 1)[0] not in errors}
            evaluable = (
                None
                if query in AMBIGUOUS
                else {
                    "tp": sorted(valid_expected & valid_got),
                    "fn": sorted(valid_expected - valid_got),
                    "fp": sorted(valid_got - valid_expected),
                    "tn_files": len(clean_negatives),
                }
            )
            row = {
                "platform": platform,
                "query": query,
                "rule": rule,
                "match": kind,
                "samples": len(samples),
                "sample_results": sample_rows,
                "expected_units": len(expected),
                "raw_expected_records": expected_raw,
                "corpus_errors": corpus_errors,
                "unscorable_fixture_files": sorted(unresolved_samples),
                "excluded_expected_records": len(corpus_errors),
                "valid_scan_files": len(samples) - len(errors),
                "evaluable": evaluable,
                "unscorable_reason": AMBIGUOUS.get(query),
                "policy_note": POLICY_NOTES.get(query),
                "tp": sorted(tp),
                "fn": sorted(fn),
                "fp": sorted(fp),
                "tn_files": len(clean_negatives),
                "parse_errors": errors,
                "failed_files": len(errors),
                "disputed": {
                    unit: reason
                    for (q, unit), reason in DISPUTED.items()
                    if q == query and (unit in fn or unit in fp)
                },
            }
            report["queries"].append(row)
            report["totals"]["excluded_expected_records"] += len(corpus_errors)
            report["evaluable_totals"]["excluded_expected_records"] += len(corpus_errors)
            report["totals"]["samples"] += len(samples)
            report["totals"]["expected_units"] += len(expected)
            report["evaluable_totals"]["scan_failed_files"] += len(errors)
            if evaluable is None:
                report["evaluable_totals"]["unscorable_queries"] += 1
                report["evaluable_totals"]["unscorable_expected_units"] += len(valid_expected)
            else:
                for key in ("tp", "fn", "fp"):
                    report["evaluable_totals"][key] += len(evaluable[key])
                report["evaluable_totals"]["tn_files"] += evaluable["tn_files"]
            for key in ("tp", "fn", "fp"):
                report["totals"][key] += len(row[key])
                report["totals"][f"{key}_{kind}"] += len(row[key])
            report["totals"]["tn_files"] += len(clean_negatives)
            report["totals"]["negative_files"] += len(negatives)
            report["totals"]["failed_files"] += len(errors)
    report["totals"] = dict(report["totals"])
    report["evaluable_totals"] = dict(report["evaluable_totals"])
    return report


def main() -> None:
    report = evaluate(Path(sys.argv[1]))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
