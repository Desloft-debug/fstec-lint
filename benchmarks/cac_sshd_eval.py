"""Сверка правил SSH с тестовыми сценариями ComplianceAsCode.

ComplianceAsCode (профили SCAP для RHEL, Ubuntu, SUSE и др.) проверяет
каждое правило набором bash-сценариев: *.pass.sh приводят sshd_config в
соответствие, *.fail.sh — нарушают его. Скрипт рендерит сценарии для
RHEL 9, выполняет их в отдельном каталоге поверх стандартного
sshd_config из OpenSSH и запускает fstec-lint.

Каждый сценарий оценивается по двум эталонам:

    cac  — метка самого сценария (fail/pass), то есть политика
           ComplianceAsCode: параметр должен быть задан явно и без
           противоречий;
    sshd — действующее значение, которое выдаёт `sshd -T` для того же
           каталога. Это проверка разбора: видит ли fstec-lint то же,
           что будет применено на сервере. Конфигурации, которые sshd
           отвергает как ошибочные, в метрики по этому эталону не входят.

Запуск:
    git clone https://github.com/ComplianceAsCode/content.git
    git clone https://github.com/openssh/openssh-portable.git
    python benchmarks/cac_sshd_eval.py content openssh-portable/sshd_config
    python benchmarks/cac_sshd_eval.py content openssh-portable/sshd_config --insecure
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
import yaml

from fstec_lint.engine import scan

PRODUCT = "rhel9"
PLATFORMS = ("multi_platform_all", "multi_platform_rhel", "Red Hat Enterprise Linux 9")

# Правило ComplianceAsCode -> правило fstec-lint и характер совпадения.
MAPPING = {
    "sshd_disable_root_login": ("S001", "partial"),
    "sshd_disable_empty_passwords": ("S003", "full"),
    "sshd_allow_only_protocol2": ("S004", "full"),
    "sshd_disable_x11_forwarding": ("S005", "full"),
    "sshd_set_max_auth_tries": ("S006", "full"),
    "sshd_set_loglevel_info": ("S008", "partial"),
}

QUIET_LEVELS = ("QUIET", "SILENT", "FATAL", "ERROR")

# Действующее значение, при котором правило обязано сработать. Protocol
# в OpenSSH 7.4+ игнорируется, поэтому по эталону sshd S004 срабатывать
# не должен никогда.
ORACLE = {
    "S001": lambda eff: eff.get("permitrootlogin") == "yes",
    "S003": lambda eff: eff.get("permitemptypasswords") == "yes",
    "S004": lambda eff: False,
    "S005": lambda eff: eff.get("x11forwarding") == "yes",
    "S006": lambda eff: int(eff.get("maxauthtries", "6")) > 4,
    "S008": lambda eff: eff.get("loglevel", "INFO").upper() in QUIET_LEVELS,
}

# Вариант «insecure»: те же сценарии, но вместо условного 'wrong_value'
# подставляется значение, которое sshd принимает и которое опасно.
INSECURE = {
    "sshd_disable_root_login": ("no", "yes"),
    "sshd_disable_empty_passwords": ("no", "yes"),
    "sshd_allow_only_protocol2": ("2", "1"),
    "sshd_disable_x11_forwarding": ("no", "yes"),
    "sshd_set_max_auth_tries": ("4", "10"),
    "sshd_set_loglevel_info": ("INFO", "QUIET"),
}

# Класс сценария по имени файла: что именно он проверяет.
CLASSES = [
    ("directory", re.compile(r"directory|drop_in|includ")),
    ("missing", re.compile(r"comment|line_not_there|main_config_missing")),
    ("conflict", re.compile(r"conflict|duplicated")),
    ("value", re.compile(r".")),
]

MACROS = r"""
{{%- macro bash_sshd_remediation(parameter, value, config_is_distributed, rule_id) -%}}
mkdir -p "{{{ sshd_config_dir }}}"
for f in "{{{ sshd_main_config_file }}}" "{{{ sshd_config_dir }}}"/*; do
  [ -f "$f" ] && sed -i "/^\s*{{{ parameter }}}\s/Id" "$f"
done
{{% if config_is_distributed == "true" -%}}
conf="{{{ sshd_config_dir }}}/00-complianceascode-hardening.conf"
echo "{{{ parameter }}} {{{ value }}}" >> "$conf"
{{%- else -%}}
sed -i "1i {{{ parameter }}} {{{ value }}}" "{{{ sshd_main_config_file }}}"
{{%- endif %}}
{{%- endmacro -%}}
{{%- macro bash_replace_or_append(file, key, value, fmt, cce_identifiers=None) -%}}
if grep -qi "^\s*{{{ key }}}\s" "{{{ file }}}"; then
  sed -i "s|^\s*{{{ key }}}\s.*|{{{ key }}} {{{ value }}}|I" "{{{ file }}}"
else
  echo "{{{ key }}} {{{ value }}}" >> "{{{ file }}}"
fi
{{%- endmacro -%}}
"""


OUTCOME = {(True, True): "tp", (True, False): "fn", (False, True): "fp", (False, False): "tn"}


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


def template_vars(rule_yml: Path) -> dict:
    # rule.yml содержит вставки Jinja, поэтому разбирается только блок template.
    text = rule_yml.read_text(encoding="utf-8")
    block = re.search(r"^template:\n(?:[ \t].*\n?|\n)+", text, re.MULTILINE)
    assert block is not None, rule_yml
    tvars = yaml.safe_load(block.group(0))["template"]["vars"]
    value = tvars.get("value")
    if tvars["datatype"] == "int":
        correct, wrong = (str(value), str(int(value) + 1)) if value else ("123", "321")
    else:
        correct, wrong = (str(value), "wrong_value") if value else ("correct_value", "wrong_value")
    return {
        "PARAMETER": tvars["parameter"],
        "CORRECT_VALUE": correct,
        "WRONG_VALUE": wrong,
        "XCCDF_VARIABLE": tvars.get("xccdf_variable"),
    }


def applicable(script: str) -> bool:
    match = re.search(r"^#\s*platform\s*=\s*(.+)$", script, re.MULTILINE)
    return match is None or any(p in match.group(1) for p in PLATFORMS)


def scenarios(cac: Path, rule: str, insecure: bool) -> dict[str, Path]:
    """Имя сценария -> файл. Сценарии правила перекрывают шаблонные."""
    found: dict[str, Path] = {}
    rule_vars = template_vars(cac / "linux_os/guide/services/ssh/ssh_server" / rule / "rule.yml")
    # Шаблонные сценарии для правил с переменной XCCDF рассчитаны на
    # значение 123, а у fstec-lint порог фиксирован, поэтому берутся
    # только сценарии самого правила.
    if insecure or not rule_vars["XCCDF_VARIABLE"]:
        for path in sorted((cac / "shared/templates/sshd_lineinfile/tests").glob("*.sh")):
            found[path.name] = path
    rule_tests = cac / "linux_os/guide/services/ssh/ssh_server" / rule / "tests"
    if rule_tests.is_dir():
        for path in sorted(rule_tests.glob("*.sh")):
            found[path.name] = path
    return found


def render(env: jinja2.Environment, text: str, context: dict) -> str:
    macros = env.from_string(MACROS)
    module = macros.make_module(context)
    full = dict(context)
    full["bash_sshd_remediation"] = module.bash_sshd_remediation
    full["bash_replace_or_append"] = module.bash_replace_or_append
    return env.from_string(text).render(full)


def classify(name: str) -> str:
    return next(label for label, pattern in CLASSES if pattern.search(name))


def run_scenario(
    env: jinja2.Environment, rule_dir: Path, scenario: Path, base: Path, context: dict
) -> tuple[dict[str, str] | None, list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        etc = root / "etc" / "ssh"
        etc.mkdir(parents=True)
        # Как в RHEL 9 и Ubuntu: drop-in каталог подключается первой строкой.
        (etc / "sshd_config").write_text(
            f"Include {etc}/sshd_config.d/*.conf\n" + base.read_text(encoding="utf-8")
        )
        work = root / "work"
        work.mkdir()
        # Вспомогательные файлы (common.sh, include.sh) лежат рядом со сценарием.
        for helper in list(scenario.parent.glob("*.sh")) + list(rule_dir.glob("*.sh")):
            if not helper.name.endswith((".pass.sh", ".fail.sh")):
                text = render(env, helper.read_text(encoding="utf-8"), context)
                (work / helper.name).write_text(text.replace("/etc/ssh", str(etc)))
        script = render(env, scenario.read_text(encoding="utf-8"), context)
        (work / "scenario.sh").write_text(script.replace("/etc/ssh", str(etc)))
        subprocess.run(["bash", "scenario.sh"], cwd=work, check=False, capture_output=True)
        shutil.rmtree(work)
        effective = sshd_effective(root, etc / "sshd_config")
        result = scan(root / "etc")
        return effective, [f.rule.id for f in result.findings]


def sshd_effective(root: Path, config: Path) -> dict[str, str] | None:
    """Вывод `sshd -T` в виде словаря; None, если sshd отверг конфигурацию."""
    key = root / "hostkey"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
    )
    proc = subprocess.run(
        ["sshd", "-T", "-f", str(config), "-h", str(key)],
        check=False,
        capture_output=True,
        text=True,
    )
    key.unlink()
    key.with_suffix(".pub").unlink()
    if proc.returncode != 0:
        return None
    pairs = (line.split(" ", 1) for line in proc.stdout.splitlines() if " " in line)
    return {k: v for k, v in pairs}


def evaluate(cac: Path, base: Path, insecure: bool = False) -> dict:
    env = environment()
    rows = []
    for rule, (lint_rule, kind) in MAPPING.items():
        rule_dir = cac / "linux_os/guide/services/ssh/ssh_server" / rule
        tvars = template_vars(rule_dir / "rule.yml")
        if insecure:
            tvars["CORRECT_VALUE"], tvars["WRONG_VALUE"] = INSECURE[rule]
        context = {
            **tvars,
            "product": PRODUCT,
            "rule_id": rule,
            "sshd_main_config_file": "/etc/ssh/sshd_config",
            "sshd_config_dir": "/etc/ssh/sshd_config.d",
            "sshd_distributed_config": "true",
            "cce_identifiers": {},
        }
        for name, path in scenarios(cac, rule, insecure).items():
            if not name.endswith((".pass.sh", ".fail.sh")):
                continue
            text = path.read_text(encoding="utf-8")
            if not applicable(text):
                continue
            effective, rules_hit = run_scenario(env, rule_dir / "tests", path, base, context)
            got = lint_rule in rules_hit
            outcome = OUTCOME[(name.endswith(".fail.sh"), got)]
            if effective is None:
                sshd_outcome = "invalid"
            else:
                sshd_outcome = OUTCOME[(ORACLE[lint_rule](effective), got)]
            rows.append(
                {
                    "cac_rule": rule,
                    "rule": lint_rule,
                    "match": kind,
                    "scenario": name,
                    "class": classify(name),
                    "outcome": outcome,
                    "sshd_outcome": sshd_outcome,
                }
            )
    totals: dict[str, int] = {}
    for row in rows:
        for key in (
            f"cac:{row['outcome']}",
            f"cac:{row['class']}:{row['outcome']}",
            f"sshd:{row['sshd_outcome']}",
        ):
            totals[key] = totals.get(key, 0) + 1
    return {"scenarios": rows, "totals": totals}


def main() -> None:
    insecure = "--insecure" in sys.argv[3:]
    report = evaluate(Path(sys.argv[1]), Path(sys.argv[2]), insecure)
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
