"""Observed input bytes matter even when corpus HEAD has not changed."""

import importlib.util
from pathlib import Path

BENCH = Path(__file__).parents[1] / "benchmarks"
spec = importlib.util.spec_from_file_location("benchmark_manifest", BENCH / "manifest.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_corpus_hashes_track_dirty_and_untracked_bytes(tmp_path):
    path = tmp_path / "fixture.yaml"
    path.write_text("first")
    before = mod.tree_manifest(tmp_path)
    path.write_text("second")
    (tmp_path / "new.yaml").write_text("new fixture")
    after = mod.tree_manifest(tmp_path)
    assert before["fixture.yaml"] != after["fixture.yaml"]
    assert "new.yaml" in after


def test_manifest_excludes_git_internals(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("not input")
    assert mod.tree_manifest(tmp_path) == {}


def test_harness_outputs_do_not_hash_their_own_manifest(tmp_path):
    for name in ("results", "outputs", ".corpora", "__pycache__"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "manifest.json").write_text("partial")
    (tmp_path / "eval.py").write_text("source")
    result = mod.tree_manifest(tmp_path, exclude=("results", "outputs", ".corpora"))
    assert set(result) == {"eval.py"}
