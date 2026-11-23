"""Local Action contract on benign paths; external tools are stubbed."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
EXPRESSIONS = {
    "${{ github.action_path }}": "selected copy",
    "${{ inputs.path }}": "каталог с пробелами",
    "${{ inputs.format }}": "json-context",
    "${{ inputs.output }}": "report.json",
    "${{ inputs.fail-on }}": "high",
}


def _document():
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def _steps():
    return [s for s in _document()["runs"]["steps"] if "run" in s]


def test_action_expressions_are_environment_values_only():
    steps = _steps()
    transported = set()
    for step in steps:
        assert step["shell"] == "bash"
        assert "${{" not in step["run"]
        transported.update(step.get("env", {}).values())
    assert set(EXPRESSIONS) == transported


def test_only_new_opted_in_report_is_uploaded():
    settings = _document()
    assert settings["inputs"]["upload-report"]["default"] == "false"
    upload = settings["runs"]["steps"][-1]
    assert "inputs.upload-report == 'true'" in upload["if"]
    assert "steps.scan.outputs.report != ''" in upload["if"]
    assert upload["with"]["path"] == "${{ steps.scan.outputs.report }}"
    assert "$ACTION_PATH" in _steps()[0]["run"]
    assert "git+" not in _steps()[0]["run"]


@pytest.mark.parametrize("status", [0, 1, 2, 3, 99])
def test_action_gate_and_handoff_do_not_depend_on_worktree_output(tmp_path, status):
    bash = shutil.which("bash")
    if bash is None or os.name == "nt":
        pytest.skip("Bash mock exercised in the Linux test matrix")
    step = _steps()[1]
    env = os.environ.copy()
    env.update({k: EXPRESSIONS[v] for k, v in step["env"].items()})
    env.update(
        RUNNER_TEMP=str(tmp_path),
        GITHUB_OUTPUT=str(tmp_path / "outputs.txt"),
        CAPTURE=str(tmp_path / "args.txt"),
        STATUS=str(status),
    )
    env.pop("BASH_ENV", None)
    env.pop("ENV", None)
    prefix = r"""
python() {
  printf '%s\0' "$@" > "$CAPTURE"
  for arg in "$@"; do
    if [[ "$arg" == --output=* && "$STATUS" != 2 ]]; then
      printf '{}\n' > "${arg#--output=}"
    fi
  done
  return "$STATUS"
}
"""
    proc = subprocess.run(
        [bash, "--noprofile", "--norc", "-c", prefix + step["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == status, proc.stderr
    args = (tmp_path / "args.txt").read_bytes().decode().split("\0")[:-1]
    assert args[:3] == ["-I", "-m", "fstec_lint"]
    assert args[-2:] == ["--", EXPRESSIONS["${{ inputs.path }}"]]
    assert "--no-inline-suppressions" in args
    assert "--strict-scope" in args
    assert "--require-input" in args
    report = Path(next(re.sub("^--output=", "", a) for a in args if a.startswith("--output=")))
    assert report.parent.parent == tmp_path
    assert report.parent.name.startswith("fstec-lint.")
    assert report.name == "report.json"
    if status in {0, 1, 3}:
        assert (tmp_path / "outputs.txt").read_text().strip() == f"report={report}"
        assert report.is_file()
    else:
        assert not (tmp_path / "outputs.txt").exists()
        assert report.exists() == (status == 99)
