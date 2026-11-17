"""Metric edge cases and external-shell safety interlock, no benchmark execution."""

import importlib.util
from pathlib import Path

import pytest


def _module(name):
    path = Path(__file__).resolve().parents[1] / "benchmarks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"benchmark_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_zero_denominators_are_null():
    summary = _module("summary")
    assert summary.metric_values(0, 0, 0) == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "precision": None,
        "recall": None,
    }
    assert summary.metric_values(0, 0, 1)["precision"] is None
    assert summary.metric_values(0, 1, 0)["recall"] is None
    assert summary.metric_values(1, 1, 3)["precision"] == 0.5
    assert summary.metric_values(1, 1, 3)["recall"] == 0.25


def test_external_shell_requires_disposable_container(monkeypatch):
    isolation = _module("isolation")
    monkeypatch.delenv("FSTEC_BENCHMARK_DISPOSABLE", raising=False)
    with pytest.raises(RuntimeError, match="disposable"):
        isolation.require_isolated_container()


def test_kics_failed_negative_is_not_true_negative(tmp_path, monkeypatch):
    """A file that could not be checked cannot inflate specificity."""
    kics = _module("kics_eval")
    monkeypatch.setattr(kics, "MAPPING", {"dockerfile": {"example": ("D001", "full")}})
    directory = tmp_path / "assets/queries/dockerfile/example/test"
    directory.mkdir(parents=True)
    (directory / "positive_expected_result.json").write_text("[]")
    (directory / "negative1").write_text("valid")
    (directory / "negative2").write_text("invalid")
    monkeypatch.setattr(
        kics,
        "run_one",
        lambda platform, sample: ([], ["parse failed"] if sample.name == "negative2" else []),
    )
    report = kics.evaluate(tmp_path)
    row = report["queries"][0]
    assert row["tn_files"] == 1
    assert row["failed_files"] == 1
    assert row["parse_errors"] == {"negative2": ["parse failed"]}
    assert report["totals"]["negative_files"] == 2
    assert report["totals"]["failed_files"] == 1
