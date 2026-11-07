"""SEC-A-02: graph budgets apply before expansion, formatting and reporting.

Small YAML semantics are compared with the isolated stock SafeLoader. Resource
oracles use specified budgets, forbidden consumers and bounded operation counts,
never a second implementation of the graph walk. All credentials are synthetic.
"""

import ctypes
import json
import os
import subprocess
import sys
import threading
from ctypes import wintypes
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml

from fstec_lint import baseline
from fstec_lint.checks import compose_checks as checks
from fstec_lint.cli import main
from fstec_lint.engine import scan
from fstec_lint.parsers import compose as parser
from fstec_lint.reporters import html, json_reporter, passport, sarif, text

SECRET = "SYNTHETIC_ALIAS_SECRET_04c8"
REPORTERS = [text, json_reporter, html, sarif, passport]


def _write(tmp_path, content):
    path = tmp_path / "compose.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def _dag(width, levels, *, key=False):
    lines = [f"x-base: &base [{SECRET}]"]
    previous = "base"
    for i in range(levels):
        name = f"a{i}"
        lines.append(f"x-{name}: &{name} [" + ", ".join(["*" + previous] * width) + "]")
        previous = name
    if key:
        lines.append("services:\n  ? *" + previous + "\n  : {privileged: true}")
    else:
        lines.append("services: {app: {environment: {PASSWORD: *" + previous + "}}}")
    result = "\n".join(lines) + "\n"
    # These fixtures bypass the OLD limits, not the new aggregate work limit.
    assert len(result.encode()) < 8192
    assert result.count("*") < 1024
    assert len(list(yaml.parse(result))) < 1000
    return result


@pytest.mark.parametrize(
    "content,expected",
    [
        (
            f"x-env: &env {{PASSWORD: {SECRET}}}\nservices:\n"
            "  app:\n    environment: *env\n  worker:\n    environment: *env\n",
            [("service:app", 4), ("service:worker", 6)],
        ),
        (
            f"x-base: &base\n  environment: {{PASSWORD: {SECRET}}}\n"
            "services:\n  app:\n    <<: *base\n    privileged: true\n",
            [("service:app", 4)],
        ),
        (
            f"services:\n  app: &app\n    environment: {{PASSWORD: {SECRET}}}\n  worker: *app\n",
            [("service:app", 3), ("service:worker", 3)],
        ),
    ],
)
def test_ordinary_alias_and_merge_semantics_and_exact_lines(tmp_path, content, expected):
    path = _write(tmp_path, content)
    parsed = parser.parse_compose(path)
    assert parsed == yaml.safe_load(content)
    direct = checks.check_secrets_in_environment(parsed)
    assert [(f[0], f[2]) for f in direct] == expected
    result = scan(path, select=["C004"])
    assert not result.errors
    assert sorted((f.location, f.line) for f in result.findings) == sorted(expected)
    assert all(f.file == str(path) and f.rule.id == "C004" for f in result.findings)
    for finding in result.findings:
        assert SECRET not in json.dumps(asdict(finding)) + repr(finding) + finding.fingerprint()
    for reporter in REPORTERS:
        rendered = reporter.render(result.findings)
        assert "C004" in rendered and SECRET not in rendered
    saved = tmp_path / "baseline.json"
    saved.write_text(baseline.render(result.findings), encoding="utf-8")
    assert json.loads(saved.read_text())["version"] == 3
    assert SECRET not in saved.read_text()
    assert baseline.apply(result.findings, baseline.load(saved)) == ([], len(expected))


def test_reused_environment_remains_shared_and_detectable(tmp_path):
    content = f"x-env: &env {{PASSWORD: {SECRET}}}\nservices:\n" + "".join(
        f"  s{i}:\n    environment: *env\n" for i in range(100)
    )
    path = _write(tmp_path, content)
    parsed = parser.parse_compose(path)
    assert len({id(s["environment"]) for s in parsed["services"].values()}) == 1
    result = scan(path, select=["C004"])
    assert not result.errors and len(result.findings) == 100
    assert {f.line for f in result.findings} == set(range(4, 203, 2))
    assert SECRET not in repr(result.findings)


@pytest.mark.parametrize("width,levels", [(8, 9), (2, 24)])
def test_dag_rejected_before_marks_or_construction(tmp_path, width, levels):
    path = _write(tmp_path, _dag(width, levels))
    code, out, err = _bounded_python(
        "from pathlib import Path\npath = Path("
        + repr(str(path))
        + ")\n"
        + """
import sys
from unittest.mock import patch
from fstec_lint.parsers import compose as p
consumers = []
operations = 0
def forbidden(*args, **kwargs):
    consumers.append('called')
    raise AssertionError('expensive consumer reached')
def count(frame, event, arg):
    global operations
    if event == 'call' and frame.f_globals is p.__dict__:
        operations += 1
        if operations > 5000:
            raise AssertionError('operation budget exceeded')
with patch.object(p, '_line_marks', forbidden), patch.object(
    p._BoundedLoader, 'construct_document', forbidden
):
    sys.setprofile(count)
    try:
        p.parse_compose(path)
    except ValueError as error:
        assert 'SYNTHETIC_ALIAS_SECRET_04c8' not in str(error) + repr(error)
    else:
        raise AssertionError('graph silently accepted')
    finally:
        sys.setprofile(None)
assert consumers == []
assert 0 < operations < 5000
print('bounded', operations)
"""
    )
    assert code == 0, (out, err)
    assert out.startswith("bounded ") and not err


def test_compound_service_key_never_stringifies_node_graph(tmp_path, monkeypatch):
    path = _write(tmp_path, _dag(3, 3, key=True))
    formatted = []

    def observed(value):
        if isinstance(value, (list, dict)):
            formatted.append(type(value).__name__)
            raise AssertionError("node graph formatted")
        return str(value)

    monkeypatch.setattr(parser, "str", observed, raising=False)
    with pytest.raises(ValueError):
        parser.parse_compose(path)
    assert formatted == []


class _NoFormat(list):
    def __str__(self):
        raise AssertionError("container stringified before validation")

    def __repr__(self):
        raise AssertionError("container repr before validation")


@pytest.mark.parametrize("check", [*checks.REGISTRY.values(), checks._env_items])
def test_direct_check_rejects_container_before_str_or_repr(check):
    value = _NoFormat([SECRET])
    data = {"services": {"app": {"environment": {"PASSWORD": value}}}}
    with pytest.raises(ValueError) as caught:
        check({"PASSWORD": value} if check is checks._env_items else data)
    assert SECRET not in str(caught.value) + repr(caught.value)


@pytest.mark.parametrize("cycle", ["self", "mutual"])
def test_cycles_rejected_before_consumers(tmp_path, monkeypatch, cycle):
    value = "&a [*a]" if cycle == "self" else "&a [&b [*a]]"
    path = _write(tmp_path, "x-cycle: " + value + "\nservices: {app: {privileged: true}}\n")
    consumers = []
    monkeypatch.setattr(parser, "_line_marks", lambda root: consumers.append(root))
    with pytest.raises(ValueError):
        parser.parse_compose(path)
    assert not consumers
    a, b = [], []
    a.append(a if cycle == "self" else b)
    if cycle == "mutual":
        b.append(a)
    for check in checks.REGISTRY.values():
        with pytest.raises(ValueError):
            check({"services": {"app": {"x-cycle": a}}})


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("surface", ["parser", "checks"])
def test_expanded_budget_boundary(tmp_path, monkeypatch, offset, surface):
    # Contract: mapping 32 + scalar 'services' (32 + 12*8) + empty mapping 32 = 192.
    module = parser if surface == "parser" else checks
    monkeypatch.setattr(module, "MAX_YAML_EXPANDED_COST", 192 + offset)
    path = _write(tmp_path, "services: {}\n")

    def invoke():
        return (
            parser.parse_compose(path)
            if surface == "parser"
            else checks.REGISTRY["C004"]({"services": {}})
        )

    if offset < 0:
        with pytest.raises(ValueError):
            invoke()
    else:
        assert invoke() == ({"services": {}} if surface == "parser" else [])


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("surface", ["parser", "checks"])
def test_budget_charges_repeated_edges(tmp_path, monkeypatch, offset, surface):
    # Two edges to the SAME ['a'] cost 32 + 2*(32 + 32 + 12) = 184.
    module = parser if surface == "parser" else checks
    monkeypatch.setattr(module, "MAX_YAML_EXPANDED_COST", 184 + offset)
    shared = ["a"]
    graph = [shared, shared]
    if surface == "parser":
        graph = yaml.compose("[&a [a], *a]")
    if offset < 0:
        with pytest.raises(ValueError):
            module._guard_graph(graph)
    else:
        module._guard_graph(graph)


@pytest.mark.parametrize("limit", [3, 4, 5])
@pytest.mark.parametrize("surface", ["parser", "checks"])
def test_effective_depth_includes_cached_alias_height(monkeypatch, limit, surface):
    # First encounter caches height 2; second encounter is one level deeper.
    module = parser if surface == "parser" else checks
    monkeypatch.setattr(module, "MAX_YAML_DEPTH", limit)
    shared = ["a"]
    graph = [shared, [shared]]
    if surface == "parser":
        graph = yaml.compose("[&a [a], [*a]]")
    if limit < 4:
        with pytest.raises(ValueError):
            module._guard_graph(graph)
    else:
        module._guard_graph(graph)


def test_textually_shallow_alias_chain_has_bounded_effective_depth(tmp_path):
    lines = ["x-0: &a0 [leaf]"]
    lines += [f"x-{i}: &a{i} [*a{i - 1}]" for i in range(1, 64)]
    path = _write(tmp_path, "\n".join(lines) + "\nservices: {}\n")
    # Composer syntax is shallow; the longest path through aliases is not.
    loader = parser._BoundedLoader(path.read_text())
    try:
        assert loader.get_single_node() is not None
    finally:
        loader.dispose()
    with pytest.raises(ValueError):
        parser.parse_compose(path)


def _windows_job():
    """Configure a child memory cap BEFORE releasing its input handshake."""

    class Basic(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_longlong),
            ("job_time", ctypes.c_longlong),
            ("flags", wintypes.DWORD),
            ("min_ws", ctypes.c_size_t),
            ("max_ws", ctypes.c_size_t),
            ("active", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class IO(ctypes.Structure):
        _fields_ = [(f"count{i}", ctypes.c_ulonglong) for i in range(6)]

    class Extended(ctypes.Structure):
        _fields_ = [
            ("basic", Basic),
            ("io", IO),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process", ctypes.c_size_t),
            ("peak_job", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    for name, args, result in [
        ("CreateJobObjectW", [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
        (
            "SetInformationJobObject",
            [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
            wintypes.BOOL,
        ),
        ("AssignProcessToJobObject", [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        ("CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
    ]:
        method = getattr(kernel, name)
        method.argtypes, method.restype = args, result
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = Extended()
    limits.basic.flags = 0x100 | 0x2000  # process memory + kill on job close
    limits.process_memory = 256 * 1024 * 1024
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        kernel.CloseHandle(job)
        raise ctypes.WinError(ctypes.get_last_error())
    return kernel, job


def _bounded_python(script):
    """256 MiB, 15-second watchdog, <=32 KiB capture per stream; no shell."""
    kernel, job = _windows_job() if os.name == "nt" else (None, None)
    bootstrap = "import sys\n"
    if os.name != "nt":
        bootstrap += (
            "import resource\nresource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))\n"
        )
    bootstrap += "exec(compile(sys.stdin.read(), '<bounded-regression>', 'exec'))\n"
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", bootstrap],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    streams, overflow = [bytearray(), bytearray()], threading.Event()

    def drain(pipe, target):
        while chunk := pipe.read(1024):
            if len(target) + len(chunk) > 32768:
                overflow.set()
                process.kill()
                return
            target.extend(chunk)

    readers = [
        threading.Thread(target=drain, args=(pipe, target), daemon=True)
        for pipe, target in zip((process.stdout, process.stderr), streams, strict=True)
    ]
    try:
        if kernel and not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        for reader in readers:
            reader.start()
        process.stdin.write(script.encode("utf-8"))
        process.stdin.close()
        process.wait(timeout=15)
        for reader in readers:
            reader.join(timeout=2)
        assert not overflow.is_set(), "bounded subprocess output exceeded capture limit"
        assert not any(reader.is_alive() for reader in readers)
        return process.returncode, *(bytes(s).decode("utf-8") for s in streams)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if kernel:
            kernel.CloseHandle(job)
        for pipe in (process.stdout, process.stderr, process.stdin):
            pipe.close()


def test_direct_wide_dag_has_bounded_operations_in_limited_process():
    code, out, err = _bounded_python("""
import sys
from fstec_lint.checks import compose_checks as c
node = ['synthetic']
for _ in range(24):
    node = [node, node]
operations = 0
def count(frame, event, arg):
    global operations
    if event == 'call' and frame.f_globals is c.__dict__:
        operations += 1
        if operations > 5000:
            raise AssertionError('operation budget exceeded')
sys.setprofile(count)
try:
    c.check_secrets_in_environment({'services': {'app': {'environment': {'PASSWORD': node}}}})
except ValueError:
    pass
else:
    raise AssertionError('graph silently accepted')
finally:
    sys.setprofile(None)
assert 0 < operations < 5000
print('bounded', operations)
""")
    assert code == 0, (out, err)
    assert out.startswith("bounded ") and not err


@pytest.mark.parametrize("fmt", ["text", "json", "html", "sarif", "passport"])
@pytest.mark.parametrize(
    "partial,fail_on,expected", [(False, "none", 3), (True, "none", 3), (True, "high", 1)]
)
def test_real_cli_alias_failure_is_private_and_never_clean(
    tmp_path, fmt, partial, fail_on, expected
):
    bad = tmp_path / "bad"
    bad.mkdir()
    _write(bad, _dag(8, 9))
    if partial:
        good = tmp_path / "good"
        good.mkdir()
        _write(good, "services:\n  app:\n    privileged: true\n")
    args = [str(tmp_path), "--select", "C002,C004", "--format", fmt, "--fail-on", fail_on]
    code, out, err = _bounded_python(
        "import sys, runpy\nsys.argv = ['fstec-lint'] + "
        + repr(args)
        + "\nrunpy.run_module('fstec_lint', run_name='__main__')\n"
    )
    assert code == expected, (out, err)
    assert err.strip() and SECRET not in out + err and "Traceback" not in err
    if partial:
        if fmt == "sarif":
            findings = json.loads(out)["runs"][0]["results"]
            assert len(findings) == 1 and findings[0]["ruleId"] == "C002"
            location = findings[0]["locations"][0]["physicalLocation"]
            reported_file = str((good / "compose.yaml").relative_to(Path.cwd()))
            assert location["artifactLocation"]["uri"] == reported_file
            assert location["region"]["startLine"] == 3
        else:
            assert "C002" in out and "service:app" in out


@pytest.mark.parametrize("fmt", REPORTERS, ids=lambda r: r.__name__.split(".")[-1])
def test_engine_alias_error_surfaces_preserve_partial_findings(tmp_path, fmt):
    bad, good = tmp_path / "bad", tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    _write(bad, "x: &a [*a]\nservices: {}\n")
    path = _write(good, f"services:\n  app:\n    environment: {{PASSWORD: {SECRET}}}\n")
    result = scan(tmp_path, select=["C004"])
    assert len(result.errors) == 1 and len(result.findings) == 1
    f = result.findings[0]
    assert (f.rule.id, f.file, f.line) == ("C004", str(path), 3)
    surfaces = (
        repr(result.errors),
        repr(f),
        json.dumps(asdict(f)),
        f.fingerprint(),
        fmt.render(result.findings),
        baseline.render(result.findings),
    )
    assert all(SECRET not in value for value in surfaces)


def test_alias_suppression_and_cli_success_usage_codes(tmp_path, capsys):
    path = _write(
        tmp_path,
        f"x-env: &env {{PASSWORD: {SECRET}}}\nservices:\n"
        "  app:\n    environment: *env # fstec-lint: ignore C004\n",
    )
    result = scan(path, select=["C004"])
    assert result.findings == [] and result.errors == [] and result.suppressed == 1
    assert main([str(path), "--select", "C004", "--fail-on", "high"]) == 0
    assert main([str(path), "--select", "UNKNOWN"]) == 2
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
