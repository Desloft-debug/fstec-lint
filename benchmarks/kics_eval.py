"""Сверка fstec-lint с размеченными примерами KICS (Docker Compose и Dockerfile).

У каждого запроса KICS есть файлы positive*/negative* и
positive_expected_result.json со строками, где запрос обязан сработать.
Для запросов, совпадающих по смыслу с правилами fstec-lint, считается:

    TP — KICS ожидает срабатывание, fstec-lint его дал;
    FN — KICS ожидает срабатывание, fstec-lint промолчал;
    FP — fstec-lint сработал там, где KICS срабатывания не ожидает;
    TN — negative-файл, где оба молчат.

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
        "volume_has_sensitive_host_directory": ("C015", "full"),
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

TARGET_NAME = {"dockerCompose": "docker-compose.yml", "dockerfile": "Dockerfile"}


def service_at(text: str, line: int) -> str | None:
    """Имя сервиса Compose, внутри которого стоит строка line (с 1)."""
    root = yaml.compose(text)
    if root is None or not hasattr(root, "value"):
        return None
    for key, value in root.value:
        if key.value != "services" or not hasattr(value, "value"):
            continue
        for skey, sval in value.value:
            start = skey.start_mark.line + 1
            end = sval.end_mark.line + 1
            if start <= line <= end:
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
    report: dict = {"queries": [], "totals": defaultdict(int)}
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
            for item in expected_raw:
                name = item.get("filename") or item.get("fileName")
                if name is None and len(positives) == 1:
                    name = positives[0].name
                sample = test_dir / name
                expected.add(unit(platform, sample, None, item["line"]))
            got = set()
            errors = {}
            for sample in samples:
                findings, errs = run_one(platform, sample)
                if errs:
                    errors[sample.name] = errs
                for f in findings:
                    if f["rule"] == rule:
                        got.add(unit(platform, sample, f["location"], f["line"]))
            negatives = [s.name for s in samples if s.name.startswith("negative")]
            clean_negatives = [
                n for n in negatives if not any(u == n or u.startswith(n + ":") for u in got)
            ]
            tp, fn, fp = expected & got, expected - got, got - expected
            row = {
                "platform": platform,
                "query": query,
                "rule": rule,
                "match": kind,
                "samples": len(samples),
                "tp": sorted(tp),
                "fn": sorted(fn),
                "fp": sorted(fp),
                "tn_files": len(clean_negatives),
                "parse_errors": errors,
                "disputed": {
                    unit: reason
                    for (q, unit), reason in DISPUTED.items()
                    if q == query and (unit in fn or unit in fp)
                },
            }
            report["queries"].append(row)
            for key in ("tp", "fn", "fp"):
                report["totals"][key] += len(row[key])
                report["totals"][f"{key}_{kind}"] += len(row[key])
            report["totals"]["tn_files"] += len(clean_negatives)
            report["totals"]["negative_files"] += len(negatives)
    report["totals"] = dict(report["totals"])
    return report


def main() -> None:
    report = evaluate(Path(sys.argv[1]))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
