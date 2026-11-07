"""Action shell contract: environment transport and actual Bash argument boundaries.

Only Bash builtins and recording functions run: PATH is empty, pip/fstec-lint
are shell stubs, no installation, external benchmark or network command runs.
This is a local composite-script test, not a GitHub-hosted Action execution.
"""

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ACTION = Path(__file__).resolve().parents[1] / "action.yml"
EXPRESSIONS = {
    "${{ github.action_ref }}": "ref",
    "${{ github.action_path }}": "action_path",
    "${{ inputs.path }}": "path",
    "${{ inputs.format }}": "format",
    "${{ inputs.output }}": "output",
    "${{ inputs.fail-on }}": "fail_on",
}
VALUES = [
    "",
    "каталог с пробелом/測試",
    "tab\tvalue",
    "${{ inputs.output }}",
    "plain",
    "directory with spaces",
    'double"quote',
    "single'quote",
    "line one\nline two",
    "$(printf SYNTHETIC_EXECUTION)",
    "`printf SYNTHETIC_EXECUTION`",
    "semi;colon & pipe| star* question? [abc] >file <file",
    "--leading-dash",
    'close"; printf SYNTHETIC_EXECUTION; #',
]


def _steps():
    return [
        s for s in yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"] if "run" in s
    ]


def test_action_expressions_are_environment_values_only():
    steps = _steps()
    assert steps
    transported = set()
    for step in steps:
        assert step["shell"] == "bash"
        assert "${{" not in step["run"], step["name"]
        transported.update(step.get("env", {}).values())
    assert set(EXPRESSIONS) <= transported


@pytest.fixture(scope="module")
def action_bash():
    candidates = [
        Path("C:/Program Files/Git/bin/bash.exe"),
        Path("C:/Program Files/Git/usr/bin/bash.exe"),
    ]
    located = shutil.which("bash")
    if located:
        candidates.append(Path(located))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            result = subprocess.run([str(candidate), "--version"], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and b"GNU bash" in result.stdout:
            return str(candidate)
    pytest.skip("No executable Bash; static assertions do not count as shell execution")


def _execute(step, values, tmp_path, bash):
    def expand(text):
        # One template expansion: expressions inside input values are data and
        # must not be expanded again by this harness.
        return re.sub(r"\$\{\{[^{}]*\}\}", lambda m: values[EXPRESSIONS[m[0]]], text)

    env = os.environ.copy()
    env.update({"PATH": "", "CAPTURE": tmp_path.as_posix(), "MSYS2_ARG_CONV_EXCL": "*"})
    env.pop("BASH_ENV", None)
    env.pop("ENV", None)
    env.update({key: expand(str(value)) for key, value in step.get("env", {}).items()})
    # Expand exactly as the Actions runner does. A vulnerable run block must
    # fail on payloads too, rather than being silently skipped by a static gate.
    script = expand(step["run"])
    prefix = """
calls=0
pip() {
  calls=$((calls + 1))
  printf '%s\\0' "$@" > "$CAPTURE/pip-$calls"
}
fstec-lint() {
  calls=$((calls + 1))
  printf '%s\\0' "$@" > "$CAPTURE/lint-$calls"
}
"""
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-c", prefix + script],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == b"", "input was evaluated as shell code"
    calls = {}
    for path in tmp_path.iterdir():
        assert path.name.startswith(("lint-", "pip-")), "unexpected shell side effect"
        calls[path.name] = [a.decode("utf-8") for a in path.read_bytes().split(b"\0")[:-1]]
    return calls


def _values():
    return {
        "ref": "v1.0.0",
        "action_path": "local action",
        "path": "project",
        "format": "json",
        "output": "report.json",
        "fail_on": "high",
    }


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("field", ["path", "output", "format", "fail_on"])
def test_action_scan_argument_boundaries(tmp_path, action_bash, value, field):
    step = next(s for s in _steps() if "--fail-on" in s["run"])
    values = {**_values(), field: value}
    calls = _execute(step, values, tmp_path, action_bash)
    assert set(calls) == {"lint-1"}
    # Standard parser without product choices: transport must preserve even
    # malformed format/fail-on values, leaving validation to the real CLI.
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    for option in ("--format", "--output", "--fail-on"):
        parser.add_argument(option)
    expected = parser.parse_args(
        [
            "--format=" + values["format"],
            "--output=" + values["output"],
            "--fail-on=" + values["fail_on"],
            "--",
            values["path"],
        ]
    )
    actual = parser.parse_args(calls["lint-1"])
    assert vars(actual) == vars(expected)


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("source", ["ref", "action_path"])
def test_action_install_argument_boundaries(tmp_path, action_bash, value, source):
    step = next(s for s in _steps() if "pip install" in s["run"])
    values = {**_values(), source: value}
    if source == "action_path":
        values["ref"] = ""
    calls = _execute(step, values, tmp_path, action_bash)
    assert set(calls) == {"pip-1", "lint-2"}
    assert calls["lint-2"] == ["--version"]
    target = (
        "fstec-lint @ git+https://github.com/Desloft-debug/fstec-lint.git@" + values["ref"]
        if values["ref"]
        else values["action_path"]
    )
    args = calls["pip-1"]
    assert args[0] == "install"
    tail = args[1:]
    if tail and tail[0] == "--":
        tail = tail[1:]
    assert tail == [target]
    if target.startswith("-"):
        assert args[1] == "--", "leading-dash local path must not become a pip option"
