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
