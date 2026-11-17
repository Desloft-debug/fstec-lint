"""Independent scoring must not manufacture query-specific detections."""

import importlib.util
from pathlib import Path


def load():
    path = Path(__file__).resolve().parents[1] / "benchmarks/kics_eval.py"
    spec = importlib.util.spec_from_file_location("kics_integrity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(tmp_path, platform, query, contents, expected):
    import json

    directory = tmp_path / "assets/queries" / platform / query / "test"
    directory.mkdir(parents=True)
    for name, body in contents.items():
        (directory / name).write_text(body)
    (directory / "positive_expected_result.json").write_text(json.dumps(expected))


def test_combined_resource_finding_cannot_prove_memory_detection(tmp_path, monkeypatch):
    kics = load()
    monkeypatch.setattr(
        kics, "MAPPING", {"dockerCompose": {"memory_not_limited": ("C012", "partial")}}
    )
    fixture(
        tmp_path,
        "dockerCompose",
        "memory_not_limited",
        {
            "positive1.yaml": "services:\n  app:\n    image: app\n",
        },
        [{"filename": "positive1.yaml", "line": 3}],
    )
    monkeypatch.setattr(
        kics,
        "run_one",
        lambda *args: (
            [
                {
                    "rule": "C012",
                    "location": "service:app",
                    "line": 3,
                }
            ],
            [],
        ),
    )
    result = kics.evaluate(tmp_path)
    row = result["queries"][0]
    assert row["tp"] == ["positive1.yaml:app"]  # historical rule-ID metric only
    assert row["evaluable"] is None
    assert row["sample_results"][0]["scoring_status"] == "unscorable"
    assert result["evaluable_totals"].get("tp", 0) == 0
    assert result["evaluable_totals"]["unscorable_expected_units"] == 1


def test_scan_error_is_not_a_valid_false_negative_or_true_positive(tmp_path, monkeypatch):
    kics = load()
    monkeypatch.setattr(kics, "MAPPING", {"dockerfile": {"example": ("D001", "full")}})
    fixture(tmp_path, "dockerfile", "example", {"positive1": "FROM x"}, [{"line": 1}])
    monkeypatch.setattr(kics, "run_one", lambda *args: ([], ["incomplete"]))
    result = kics.evaluate(tmp_path)
    row = result["queries"][0]
    assert row["fn"] == ["positive1"]  # never rewrite the raw historical metric
    assert row["evaluable"]["fn"] == []
    assert row["valid_scan_files"] == 0
    assert result["evaluable_totals"]["scan_failed_files"] == 1
    monkeypatch.setattr(
        kics,
        "run_one",
        lambda *args: (
            [
                {
                    "rule": "D001",
                    "location": "file",
                    "line": 1,
                }
            ],
            ["incomplete"],
        ),
    )
    row = kics.evaluate(tmp_path)["queries"][0]
    assert row["tp"] == ["positive1"]
    assert row["evaluable"]["tp"] == []


def test_units_and_policy_scope_are_explicit(tmp_path, monkeypatch):
    kics = load()
    assert kics.MAPPING["dockerCompose"]["volume_has_sensitive_host_directory"][1] == "partial"
    assert "cpu" in kics.AMBIGUOUS["memory_not_limited"].lower()
    monkeypatch.setattr(kics, "MAPPING", {"dockerfile": {"example": ("D001", "full")}})
    fixture(tmp_path, "dockerfile", "example", {"negative1": "FROM x"}, [])
    monkeypatch.setattr(kics, "run_one", lambda *args: ([], []))
    result = kics.evaluate(tmp_path)
    assert result["metric_units"]["accuracy"] is None
    assert result["totals"]["samples"] == 1
    assert result["totals"]["expected_units"] == 0
    assert result["evaluable_totals"]["tn_files"] == 1


def test_malformed_service_shape_has_file_unit_instead_of_crashing():
    kics = load()
    for text in ("[]", "null", "services: null", "services: []", "services: {image: docker}"):
        assert kics.service_at(text, 20) is None


def test_service_boundaries_exclude_next_header_and_root_key():
    kics = load()
    text = "services:\n  first:\n    image: a\n  second:\n    image: b\nvolumes: {}\n"
    assert kics.service_at(text, 0) is None
    assert kics.service_at(text, 1) is None
    assert kics.service_at(text, 2) == "first"
    assert kics.service_at(text, 3) == "first"
    assert kics.service_at(text, 4) == "second"
    assert kics.service_at(text, 5) == "second"
    assert kics.service_at(text, 6) is None
    assert kics.service_at(text, 7) is None


def test_service_end_without_newline_and_inline_value():
    kics = load()
    for text in ("services:\n  app:\n    image: a", "services:\n  app:\n    image: a\n"):
        assert kics.service_at(text, 3) == "app"
        assert kics.service_at(text, 4) is None
    for text in ("services:\n  app: {image: a}", "services:\n  app: {image: a}\n"):
        assert kics.service_at(text, 2) == "app"
        assert kics.service_at(text, 3) is None


def test_missing_or_unsupported_expected_fixture_is_not_false_negative(tmp_path, monkeypatch):
    kics = load()
    for platform, name in [("dockerfile", "positive1"), ("dockerCompose", "positive1.yaml")]:
        monkeypatch.setattr(kics, "MAPPING", {platform: {"example": ("D001", "full")}})
        fixture(
            tmp_path,
            platform,
            "example",
            {name: "services:\n  app:\n    image: a\n", "positive2.txt": "not scanned"},
            [
                {"filename": name, "line": 3},
                {"filename": "positive_missing", "line": 1},
                {"filename": "positive2.txt", "line": 1},
            ],
        )
        calls = []

        def scan_sample(platform, sample, calls=calls):
            calls.append(sample.name)
            return [], []

        monkeypatch.setattr(kics, "run_one", scan_sample)
        result = kics.evaluate(tmp_path)
        row = result["queries"][0]
        assert calls == [name]
        assert len(row["fn"]) == len(row["evaluable"]["fn"]) == 1
        assert row["excluded_expected_records"] == 2
        assert len(row["corpus_errors"]) == 2
        assert result["evaluable_totals"]["excluded_expected_records"] == 2
        assert all(error["scoring_status"] == "unscorable" for error in row["corpus_errors"])


def test_scanner_exception_is_failed_scan_and_other_samples_continue(tmp_path, monkeypatch):
    kics = load()
    monkeypatch.setattr(kics, "MAPPING", {"dockerfile": {"example": ("D001", "full")}})
    fixture(
        tmp_path,
        "dockerfile",
        "example",
        {"positive1": "FROM a", "positive2": "FROM b"},
        [{"filename": "positive1", "line": 1}, {"filename": "positive2", "line": 1}],
    )
    calls = []

    def scan_sample(platform, sample):
        calls.append(sample.name)
        if sample.name == "positive1":
            raise OSError("fixture unavailable")
        return [{"rule": "D001", "location": "file", "line": 1}], []

    monkeypatch.setattr(kics, "run_one", scan_sample)
    row = kics.evaluate(tmp_path)["queries"][0]
    assert calls == ["positive1", "positive2"]
    assert row["sample_results"][0]["scan_status"] == "failed"
    assert row["parse_errors"]["positive1"] == ["OSError: fixture unavailable"]
    assert row["evaluable"]["fn"] == []
    assert row["evaluable"]["tp"] == ["positive2"]


def test_alias_service_uses_own_key_range_not_anchor_marks():
    kics = load()
    base = "services:\n  first: &shared\n    privileged: true\n  second: *shared"
    for ending in ("", "\n", "\nvolumes: {}\n"):
        text = base + ending
        assert kics.service_at(text, 2) == "first"
        assert kics.service_at(text, 3) == "first"
        assert kics.service_at(text, 4) == "second"
        assert kics.service_at(text, 5) is None
    text = base + "\n  third: *shared\n"
    assert kics.service_at(text, 4) == "second"
    assert kics.service_at(text, 5) == "third"
    assert kics.service_at(text, 6) is None


def test_alias_expected_header_matches_service_location(tmp_path, monkeypatch):
    kics = load()
    monkeypatch.setattr(kics, "MAPPING", {"dockerCompose": {"example": ("C002", "full")}})
    fixture(
        tmp_path,
        "dockerCompose",
        "example",
        {
            "positive1.yaml": (
                "services:\n  first: &shared\n    privileged: true\n  second: *shared\n"
            )
        },
        [{"filename": "positive1.yaml", "line": 4}],
    )
    monkeypatch.setattr(
        kics,
        "run_one",
        lambda *args: ([{"rule": "C002", "location": "service:second", "line": 4}], []),
    )
    row = kics.evaluate(tmp_path)["queries"][0]
    assert row["tp"] == ["positive1.yaml:second"]
    assert row["fn"] == row["fp"] == []
    assert row["evaluable"]["tp"] == ["positive1.yaml:second"]
    assert row["evaluable"]["fn"] == row["evaluable"]["fp"] == []


def test_inline_service_ambiguity_excluded_not_mislabeled(tmp_path, monkeypatch):
    kics = load()
    text = "services: {first: {privileged: true}, second: {privileged: true}}\n"
    assert kics.service_at(text, 1) is None
    monkeypatch.setattr(kics, "MAPPING", {"dockerCompose": {"example": ("C002", "full")}})
    fixture(
        tmp_path,
        "dockerCompose",
        "example",
        {"positive1.yaml": text},
        [{"filename": "positive1.yaml", "line": 1}],
    )
    monkeypatch.setattr(
        kics,
        "run_one",
        lambda *args: ([{"rule": "C002", "location": "service:second", "line": 1}], []),
    )
    row = kics.evaluate(tmp_path)["queries"][0]
    assert row["tp"] == row["fn"] == row["fp"] == []
    assert row["evaluable"]["tp"] == row["evaluable"]["fn"] == row["evaluable"]["fp"] == []
    assert row["corpus_errors"][0]["scoring_status"] == "unscorable"
    assert row["sample_results"][0]["scoring_status"] == "unscorable"
    assert row["raw_expected_records"] == [{"filename": "positive1.yaml", "line": 1}]
    assert row["sample_results"][0]["raw_findings"] == [
        {"rule": "C002", "location": "service:second", "line": 1}
    ]
