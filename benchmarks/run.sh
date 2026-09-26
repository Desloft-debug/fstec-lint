#!/usr/bin/env bash
# Воспроизведение сверки. Нужны git, bash, python3 с jinja2, OpenSSH (sshd, ssh-keygen)
# и rsyslog (для стандартного /etc/rsyslog.conf).
# Версии корпусов закреплены, чтобы результаты совпадали с benchmarks/results.
set -euo pipefail

KICS_REV=453066aa9c66014ad7aee7dd0149ba1944c78050
CAC_REV=f9568564d3c63c23d275538869f28c635f468c26
OPENSSH_REV=ccc26c76cd47ca224ff5e4ef8b96007b65ff0b4e

here="$(cd "$(dirname "$0")" && pwd)"
work="${1:-$here/.corpora}"
mkdir -p "$work" "$here/results"

fetch() {  # каталог, репозиторий, ревизия, пути
  local dir="$1" repo="$2" rev="$3"; shift 3
  if [ ! -d "$work/$dir" ]; then
    git clone -q --filter=blob:none --no-checkout "$repo" "$work/$dir"
    git -C "$work/$dir" sparse-checkout set --no-cone "$@"
  fi
  git -C "$work/$dir" checkout -q "$rev"
}

fetch kics https://github.com/Checkmarx/kics.git "$KICS_REV" \
  /assets/queries/dockerfile /assets/queries/dockerCompose
fetch cac https://github.com/ComplianceAsCode/content.git "$CAC_REV" \
  /linux_os/guide/services/ssh/ssh_server /shared/templates/sshd_lineinfile \
  /shared/templates/accounts_password /shared/macros \
  /linux_os/guide/system/accounts/accounts-restrictions/password_expiration \
  /linux_os/guide/system/accounts/accounts-restrictions/account_expiration \
  /linux_os/guide/system/accounts/accounts-pam/password_quality \
  /linux_os/guide/system/logging/rsyslog_sending_messages
fetch openssh https://github.com/openssh/openssh-portable.git "$OPENSSH_REV" /sshd_config

mkdir -p /run/sshd 2>/dev/null || true
python3 "$here/kics_eval.py" "$work/kics" > "$here/results/kics.json"
python3 "$here/cac_sshd_eval.py" "$work/cac" "$work/openssh/sshd_config" > "$here/results/cac_sshd.json"
python3 "$here/cac_sshd_eval.py" "$work/cac" "$work/openssh/sshd_config" --insecure \
  > "$here/results/cac_sshd_insecure.json"
# Стандартный rsyslog.conf дистрибутива (пакет rsyslog), поверх которого
# выполняются сценарии rsyslog.
python3 "$here/cac_linux_eval.py" "$work/cac" "${RSYSLOG_CONF:-/etc/rsyslog.conf}" \
  > "$here/results/cac_linux.json"
python3 "$here/summary.py" "$here/results"
