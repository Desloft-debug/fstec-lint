"""Сверка правил A001, A002, A003, R001 со сценариями ComplianceAsCode.

Сценарии *.pass.sh и *.fail.sh рендерятся для RHEL 9 и выполняются в
отдельном каталоге: пути /etc/... переписываются на временный корень.
Метка сценария (pass/fail) служит эталоном.

Пороги у fstec-lint и в профилях ComplianceAsCode разные, поэтому:

- для login.defs берутся сценарии с порогом не выше 90 дней (профили
  STIG и standard); сценарии профиля CIS с порогом 365 дней пропускаются,
  там срок 365 дней допустим, а для fstec-lint это нарушение;
- для pwquality в шаблонные сценарии подставляются пороги fstec-lint
  (minlen 8, minclass 3) вместо условных 1 и -1; находка засчитывается,
  если в ней упомянут проверяемый параметр;
- сценарии /etc/default/useradd выполняются поверх файла RHEL 9 сразу
  после установки (INACTIVE=-1).

Запуск:
    python benchmarks/cac_linux_eval.py content /etc/rsyslog.conf
Второй аргумент — стандартный rsyslog.conf дистрибутива, поверх которого
выполняются сценарии rsyslog.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import jinja2
from isolation import require_isolated_container

from fstec_lint.engine import scan

PRODUCT = "rhel9"
PLATFORMS = ("multi_platform_all", "multi_platform_rhel", "Red Hat Enterprise Linux 9")
OUTCOME = {(True, True): "tp", (True, False): "fn", (False, True): "fp", (False, False): "tn"}

RULE_DIRS = {
    "accounts_maximum_age_login_defs": "linux_os/guide/system/accounts/accounts-restrictions/"
    "password_expiration/accounts_maximum_age_login_defs",
    "accounts_password_pam_minlen": "linux_os/guide/system/accounts/accounts-pam/"
    "password_quality/password_quality_pwquality/accounts_password_pam_minlen",
    "accounts_password_pam_minclass": "linux_os/guide/system/accounts/accounts-pam/"
    "password_quality/password_quality_pwquality/accounts_password_pam_minclass",
    "rsyslog_remote_loghost": "linux_os/guide/system/logging/rsyslog_sending_messages/"
    "rsyslog_remote_loghost",
    "account_disable_post_pw_expiration": "linux_os/guide/system/accounts/"
    "accounts-restrictions/account_expiration/account_disable_post_pw_expiration",
}

# Правило ComplianceAsCode -> (правило fstec-lint, подстрока в находке или None).
MAPPING = {
    "accounts_maximum_age_login_defs": ("A001", None),
    "accounts_password_pam_minlen": ("A002", "minlen"),
    "accounts_password_pam_minclass": ("A002", "классов"),
    "rsyslog_remote_loghost": ("R001", None),
    "account_disable_post_pw_expiration": ("A003", None),
}

# /etc/default/useradd в RHEL 9 сразу после установки.
USERADD_RHEL9 = (
    "GROUP=100\nHOME=/home\nINACTIVE=-1\nEXPIRE=\nSHELL=/bin/bash\n"
    "SKEL=/etc/skel\nCREATE_MAIL_SPOOL=yes\n"
)

# Значения для шаблона accounts_password: (верное, неверное).
PWQUALITY_VALUES = {"minlen": ("8", "7"), "minclass": ("3", "2")}
MAX_LOGIN_DEFS_DAYS = 90


def environment() -> jinja2.Environment:
    return jinja2.Environment(
        block_start_string="{{%",
        block_end_string="%}}",
        variable_start_string="{{{",
        variable_end_string="}}}",
        comment_start_string="{{#",
        comment_end_string="#}}",
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
    )


def applicable(script: str) -> bool:
    match = re.search(r"^#\s*platform\s*=\s*(.+)$", script, re.MULTILINE)
    return match is None or any(p in match.group(1) for p in PLATFORMS)


def login_defs_variable(script: str) -> int | None:
    match = re.search(r"var_accounts_maximum_age_login_defs=(\d+)", script)
    return int(match.group(1)) if match else None


def scenarios(cac: Path, rule: str) -> list[Path]:
    rule_tests = cac / RULE_DIRS[rule] / "tests"
    if rule.startswith("accounts_password_pam_"):
        rule_tests = cac / "shared/templates/accounts_password/tests"
    return sorted(p for p in rule_tests.glob("*.sh") if p.name.endswith((".pass.sh", ".fail.sh")))


def context(env: jinja2.Environment, cac: Path, rule: str) -> dict:
    ctx: dict = {
        "product": PRODUCT,
        "families": ["rhel"],
        "rule_id": rule,
        "login_defs_path": "/etc/login.defs",
        "pwquality_path": "/etc/security/pwquality.conf",
    }
    if rule.startswith("accounts_password_pam_"):
        variable = rule.rsplit("_", 1)[1]
        correct, wrong = PWQUALITY_VALUES[variable]
        ctx.update(
            VARIABLE=variable,
            TEST_VAR_VALUE=correct,
            TEST_CORRECT_VALUE=correct,
            TEST_WRONG_VALUE=wrong,
            TEST_WRONG_VS_ZERO_VALUE=wrong,
            ZERO_COMPARISON_OPERATION=None,
        )
    macros = (cac / "shared/macros/20-test-scenarios.jinja").read_text(encoding="utf-8")
    module = env.from_string(macros).make_module(ctx)
    for name in ("setup_rsyslog_common", "setup_rsyslog_remote_loghost"):
        ctx[name] = getattr(module, name)
    return ctx


SETUP_TIMEOUT = 30
LOG_LIMIT = 65536


def execute_setup(work: Path) -> dict:
    """Run only inside the disposable container. Preserve failures, bound runtime."""
    require_isolated_container()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(
            ["bash", "-e", "-o", "pipefail", "scenario.sh"],
            cwd=work,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        timed_out = False
        try:
            proc.wait(timeout=SETUP_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Also remove children left behind by a successful shell. A child
            # escaping this session still requires per-container supervision.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        logs = {}
        for name, stream in (("stdout", stdout), ("stderr", stderr)):
            size = stream.tell()
            stream.seek(0)
            logs[name] = stream.read(LOG_LIMIT).decode("utf-8", errors="replace")
            logs[name + "_truncated"] = size > LOG_LIMIT
        return {
            "status": "timeout" if timed_out else "ok" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            **logs,
            "shell": "bash -e -o pipefail",
            "timeout_seconds": SETUP_TIMEOUT,
            "postconditions": "not_independently_verified",
        }


def snapshot(root: Path) -> dict:
    files = {}
    for path in sorted((root / "etc").rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if len(files) >= 200:
            files["__snapshot_truncated__"] = True
            break
        with path.open("rb") as stream:
            data = stream.read(LOG_LIMIT + 1)
        files[str(path.relative_to(root))] = {
            "prefix_sha256": hashlib.sha256(data[:LOG_LIMIT]).hexdigest(),
            "text": data[:LOG_LIMIT].decode("utf-8", errors="replace"),
            "truncated": len(data) > LOG_LIMIT,
        }
    return files


def pwquality_oracle(root: Path, rule: str) -> dict:
    """Optional real libpwquality binding, not a reimplementation of its parser."""
    if not rule.startswith("accounts_password_pam_"):
        return {"status": "not_available", "reason": "no independent runtime oracle"}
    try:
        import pwquality
    except ImportError:
        return {"status": "not_available", "reason": "python pwquality binding not installed"}
    parameter = rule.rsplit("_", 1)[1]
    try:
        settings = pwquality.PWQSettings()
        settings.read_config(str(root / "etc/security/pwquality.conf"))
        value = getattr(settings, parameter)
    except Exception as exc:
        return {"status": "failed", "reason": str(exc)}
    return {
        "status": "ok",
        "parameter": parameter,
        "effective_value": value,
        "expected_violation": value < int(PWQUALITY_VALUES[parameter][0]),
        "scope": "libpwquality read_config; no PAM overrides or authentication execution",
    }


def run(script: str, rsyslog_base: Path) -> tuple[Path, tempfile.TemporaryDirectory, dict]:
    require_isolated_container()
    holder = tempfile.TemporaryDirectory()
    root = Path(holder.name)
    etc = root / "etc"
    (etc / "security").mkdir(parents=True)
    (etc / "rsyslog.d").mkdir()
    (etc / "default").mkdir()
    (etc / "default" / "useradd").write_text(USERADD_RHEL9, encoding="utf-8")
    text = rsyslog_base.read_text(encoding="utf-8").replace("/etc/", f"{etc}/")
    (etc / "rsyslog.conf").write_text(text, encoding="utf-8")
    work = root / "work"
    work.mkdir()
    (work / "scenario.sh").write_text(re.sub(r"(?<![\w.])/etc/", f"{etc}/", script))
    setup = execute_setup(work)
    setup["rendered_script"] = (work / "scenario.sh").read_text()
    return root, holder, setup


def evaluate(cac: Path, rsyslog_base: Path) -> dict:
    env = environment()
    rows = []
    for rule, (lint_rule, marker) in MAPPING.items():
        try:
            ctx = context(env, cac, rule)
            context_error = None
        except jinja2.TemplateError as exc:
            ctx, context_error = {}, str(exc)
        for path in scenarios(cac, rule):
            raw = path.read_text(encoding="utf-8")
            row = {
                "cac_rule": rule,
                "rule": lint_rule,
                "scenario": path.name,
                "source": str(path.relative_to(cac)),
                "source_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "raw_expected_violation": path.name.endswith(".fail.sh"),
                "outcome": "not_evaluated",
                "runtime_outcome": "not_available",
            }
            rows.append(row)
            if not applicable(raw):
                row.update(outcome="skipped", reason="platform not applicable")
                continue
            if rule == "accounts_maximum_age_login_defs":
                limit = login_defs_variable(raw)
                if limit is not None and limit > MAX_LOGIN_DEFS_DAYS:
                    row.update(
                        outcome="skipped", reason=f"profile threshold {limit} exceeds lint policy"
                    )
                    continue
            try:
                if context_error:
                    raise jinja2.UndefinedError(context_error)
                script = env.from_string(raw).render(ctx)
            except jinja2.TemplateError as exc:
                row.update(outcome="render_failed", reason=str(exc))
                continue
            row["rendered_sha256"] = hashlib.sha256(script.encode()).hexdigest()
            if not applicable(script):
                row.update(outcome="skipped", reason="rendered platform not applicable")
                continue
            try:
                root, holder, setup = run(script, rsyslog_base)
            except OSError as exc:
                row.update(outcome="setup_failed", reason=str(exc))
                continue
            with holder:
                row["setup"] = setup
                row["snapshot"] = snapshot(root)
                if setup["status"] != "ok":
                    row.update(outcome="setup_failed", reason=setup["status"])
                    continue
                try:
                    result = scan(root / "etc")
                except Exception as exc:
                    row.update(outcome="scan_failed", reason=str(exc))
                    continue
                findings = [f for f in result.findings if f.rule.id == lint_rule]
                row["scan"] = {
                    "errors": [str(e) for e in result.errors],
                    "findings": [{"rule": f.rule.id, "detail": f.detail} for f in findings],
                }
                if result.errors:
                    row.update(outcome="scan_failed", reason="incomplete scan")
                    continue
                got = any(marker is None or marker in f.detail for f in findings)
                row["observed_violation"] = got
                row["outcome"] = OUTCOME[(row["raw_expected_violation"], got)]
                oracle = pwquality_oracle(root, rule)
                row["runtime_oracle"] = oracle
                if oracle["status"] == "ok":
                    expected = oracle["expected_violation"]
                    row["runtime_outcome"] = OUTCOME[(expected, got)]
                    row["policy_runtime_disagreement"] = expected != row["raw_expected_violation"]
    totals: dict[str, int] = {}
    for row in rows:
        totals[row["outcome"]] = totals.get(row["outcome"], 0) + 1
    valid = sum(totals.get(k, 0) for k in OUTCOME.values())
    return {
        "schema_version": 2,
        "scenarios": rows,
        "totals": totals,
        "counts": {
            "discovered": len(rows),
            "classified_raw": valid,
            "not_classified_raw": len(rows) - valid,
            "runtime_classified": sum(r["runtime_outcome"] in OUTCOME.values() for r in rows),
        },
        "limitations": [
            "adapted corpus, not full CaC profile",
            "setup exit zero does not prove all postconditions",
            "A002 parameter matching uses diagnostic text; stable subtype unavailable",
            "runtime oracle optional and limited to pwquality config, not PAM",
        ],
    }


def main() -> None:
    require_isolated_container()
    report = evaluate(Path(sys.argv[1]), Path(sys.argv[2]))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
