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

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import jinja2

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


def run(script: str, rsyslog_base: Path) -> tuple[Path, tempfile.TemporaryDirectory]:
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
    subprocess.run(["bash", "scenario.sh"], cwd=work, check=False, capture_output=True)
    shutil.rmtree(work)
    return root, holder


def evaluate(cac: Path, rsyslog_base: Path) -> dict:
    env = environment()
    rows = []
    for rule, (lint_rule, marker) in MAPPING.items():
        ctx = context(env, cac, rule)
        for path in scenarios(cac, rule):
            raw = path.read_text(encoding="utf-8")
            skipped = None
            if rule == "accounts_maximum_age_login_defs":
                limit = login_defs_variable(raw)
                if limit is not None and limit > MAX_LOGIN_DEFS_DAYS:
                    skipped = f"порог профиля {limit} дней больше порога fstec-lint"
            try:
                script = env.from_string(raw).render(ctx)
            except jinja2.UndefinedError:
                if not applicable(raw):
                    continue
                # Сценарий меняет настройки PAM макросами, которые здесь не
                # воспроизводятся; pwquality.conf он не затрагивает.
                skipped = "настройка PAM, а не pwquality.conf"
                script = ""
            if script and not applicable(script):
                continue
            if skipped:
                rows.append(
                    {
                        "cac_rule": rule,
                        "rule": lint_rule,
                        "scenario": path.name,
                        "outcome": "skipped",
                        "reason": skipped,
                    }
                )
                continue
            root, holder = run(script, rsyslog_base)
            with holder:
                findings = [f for f in scan(root).findings if f.rule.id == lint_rule]
            got = any(marker is None or marker in f.detail for f in findings)
            rows.append(
                {
                    "cac_rule": rule,
                    "rule": lint_rule,
                    "scenario": path.name,
                    "outcome": OUTCOME[(path.name.endswith(".fail.sh"), got)],
                }
            )
    totals: dict[str, int] = {}
    for row in rows:
        totals[row["outcome"]] = totals.get(row["outcome"], 0) + 1
    return {"scenarios": rows, "totals": totals}


def main() -> None:
    report = evaluate(Path(sys.argv[1]), Path(sys.argv[2]))
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
