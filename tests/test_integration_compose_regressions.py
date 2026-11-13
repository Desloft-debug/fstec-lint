"""Behavioral regression checks: capability, privilege, resources, health and bind policy.

Labels describe the project acceptance policy; they are not regulatory claims.
No Docker daemon or shell is used. Red and candidate runs use identical cases.
"""

import pytest

from fstec_lint.engine import scan

CASES = [
    ("C003", "missing-drop", "image: alpine:3.20", True),
    ("C003", "empty-drop", "cap_drop: []", True),
    ("C003", "partial-drop", "cap_drop: [NET_RAW]", True),
    ("C003", "all-dropped", "cap_drop: [ALL]", False),
    ("C003", "safe-add", "cap_drop: [ALL]\ncap_add: [CHOWN]", False),
    ("C003", "admin", "cap_drop: [ALL]\ncap_add: [SYS_ADMIN]", True),
    ("C003", "ptrace", "cap_drop: [ALL]\ncap_add: [SYS_PTRACE]", True),
    ("C003", "net-admin", "cap_drop: [ALL]\ncap_add: [NET_ADMIN]", True),
    ("C010", "false-colon", 'security_opt: ["no-new-privileges:false"]', True),
    ("C010", "false-equals", 'security_opt: ["no-new-privileges=false"]', True),
    ("C010", "unrelated", 'security_opt: ["label:disable"]', True),
    ("C010", "true-colon", 'security_opt: ["no-new-privileges:true"]', False),
    ("C010", "true-equals", 'security_opt: ["no-new-privileges=true"]', False),
    ("C010", "bare-enabled", 'security_opt: ["no-new-privileges"]', False),
    ("C012", "memory-only", "mem_limit: 256m", True),
    ("C012", "cpu-only", "cpus: 1", True),
    ("C012", "deploy-memory-only", "deploy: {resources: {limits: {memory: 256M}}}", True),
    ("C012", "deploy-cpu-only", 'deploy: {resources: {limits: {cpus: "1"}}}', True),
    ("C012", "both", "mem_limit: 256m\ncpus: 1", False),
    ("C012", "quota", "mem_limit: 256m\ncpu_quota: 50000", False),
    ("C012", "deploy-both", 'deploy: {resources: {limits: {memory: 256M, cpus: "1"}}}', False),
    ("C013", "none-list", "healthcheck: {test: [NONE]}", True),
    ("C013", "disabled", "healthcheck: {disable: true}", True),
    ("C013", "missing", "image: alpine:3.20", True),
    ("C013", "cmd-list", 'healthcheck: {test: [CMD, "true"]}', False),
    ("C013", "cmd-shell", 'healthcheck: {test: [CMD-SHELL, "exit 0"]}', False),
    ("C013", "string", 'healthcheck: {test: "exit 0"}', False),
    ("C015", "ssl-nested", 'volumes: ["/etc/ssl:/data:ro"]', True),
    ("C015", "proc-nested", 'volumes: ["/proc/sys:/data"]', True),
    ("C015", "root-ssh", 'volumes: ["/root/.ssh:/data:ro"]', True),
    ("C015", "long-bind", "volumes: [{type: bind, source: /etc/ssl, target: /data}]", True),
    ("C015", "long-src", "volumes: [{type: bind, src: /etc/ssl, target: /data}]", True),
    ("C015", "anonymous", 'volumes: ["/etc"]', False),
    ("C015", "named", 'volumes: ["data:/etc"]', False),
    ("C015", "long-volume", "volumes: [{type: volume, source: data, target: /etc}]", False),
    ("C015", "safe-bind", 'volumes: ["./data:/data:ro"]', False),
    ("C015", "prefix-boundary", 'volumes: ["/etc-backup:/data:ro"]', False),
]


@pytest.mark.parametrize("rule,case,body,reported", CASES, ids=[c[1] for c in CASES])
def test_observable_compose_policy(tmp_path, rule, case, body, reported):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services:\n  app:\n    " + body.replace("\n", "\n    ") + "\n", encoding="utf-8"
    )
    result = scan(path, select=[rule])
    assert not result.errors, result.errors
    assert bool(result.findings) is reported, (rule, case, result)
    assert all(f.rule.id == rule and f.file == str(path) and f.line for f in result.findings)


@pytest.mark.parametrize("option", ["device", "mountpoint"])
@pytest.mark.parametrize("source,reported", [("/etc/ssl", True), ("./data", False)])
def test_top_level_bind_volume(tmp_path, option, source, reported):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services:\n  app:\n    volumes: [data:/data]\nvolumes:\n  data:\n"
        f"    driver_opts: {{type: none, o: bind, {option}: {source}}}\n",
        encoding="utf-8",
    )
    result = scan(path, select=["C015"])
    assert not result.errors
    assert bool(result.findings) is reported


def test_unmounted_sensitive_named_volume_is_not_a_service_mount(tmp_path):
    path = tmp_path / "compose.yaml"
    path.write_text(
        "services: {app: {image: alpine}}\nvolumes:\n"
        "  unused: {driver_opts: {type: none, o: bind, device: /etc/ssl}}\n",
        encoding="utf-8",
    )
    result = scan(path, select=["C015"])
    assert not result.errors and not result.findings
