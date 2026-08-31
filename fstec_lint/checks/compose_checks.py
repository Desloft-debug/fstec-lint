"""Проверки для docker-compose.yml.

Каждая функция принимает распарсенный dict compose-файла и возвращает список
кортежей (location, detail) — по одному на каждое найденное нарушение.
Метаданные (severity, мера ФСТЭК, remediation) хранятся отдельно, в
fstec_lint/rules/compose_rules.yaml, и связываются по идентификатору правила
через REGISTRY внизу файла.
"""

from __future__ import annotations

import re

SENSITIVE_PORTS = {"5432", "3306", "6379", "27017", "9200", "1433", "11211"}
SECRET_KEY_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE)
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}
SAFE_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _services(compose: dict) -> dict:
    return (compose or {}).get("services", {}) or {}


def check_root_user(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        if "user" not in svc:
            findings.append((f"service:{name}", "нет директивы 'user' — процесс в контейнере выполняется от root"))
    return findings


def check_privileged(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("privileged") is True:
            findings.append((f"service:{name}", "сервис запущен с privileged: true"))
    return findings


def check_dangerous_capabilities(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        caps = svc.get("cap_add") or []
        bad = [str(c) for c in caps if str(c).upper() in DANGEROUS_CAPS]
        if bad:
            findings.append((f"service:{name}", f"добавлены опасные capabilities: {', '.join(bad)}"))
    return findings


def _env_items(env) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(env, dict):
        for k, v in env.items():
            items.append((str(k), "" if v is None else str(v)))
    elif isinstance(env, list):
        for entry in env:
            if isinstance(entry, str) and "=" in entry:
                k, v = entry.split("=", 1)
                items.append((k, v))
    return items


def check_secrets_in_environment(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for key, value in _env_items(svc.get("environment")):
            if key.upper().endswith(("_FILE", "_FILENAME")):
                # docker secrets convention: значение — это путь, а не сам секрет
                continue
            if value and not value.startswith("${") and SECRET_KEY_RE.search(key):
                findings.append((f"service:{name}", f"переменная {key} содержит секрет в открытом виде"))
    return findings


def _port_is_exposed(entry) -> tuple[bool, str]:
    """Возвращает (публикуется_на_всех_интерфейсах, container_port)."""
    if isinstance(entry, dict):
        target = str(entry.get("target", ""))
        published = entry.get("published")
        host_ip = entry.get("host_ip")
        if published in (None, ""):
            return False, target
        return host_ip not in SAFE_LOOPBACK, target

    parts = str(entry).split(":")
    if len(parts) == 3:
        host_ip, _host_port, container_port = parts
    elif len(parts) == 2:
        host_ip, container_port = None, parts[1]
    else:
        host_ip, container_port = None, parts[0]
    container_port = container_port.split("/")[0]
    return host_ip not in SAFE_LOOPBACK, container_port


def check_exposed_sensitive_ports(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for port_entry in svc.get("ports") or []:
            exposed, container_port = _port_is_exposed(port_entry)
            if exposed and container_port in SENSITIVE_PORTS:
                findings.append((f"service:{name}", f"порт {port_entry} публикуется на все интерфейсы хоста"))
    return findings


def check_latest_tag(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        image = svc.get("image")
        if not image:
            continue
        if "@sha256:" in image:
            continue
        last_segment = image.split("/")[-1]
        if ":" not in last_segment or last_segment.endswith(":latest"):
            findings.append((f"service:{name}", f"образ '{image}' использует тег :latest либо не закреплён по версии/digest"))
    return findings


def check_host_network(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("network_mode") == "host":
            findings.append((f"service:{name}", "сервис использует network_mode: host"))
    return findings


def check_docker_socket_mount(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for vol in svc.get("volumes") or []:
            source = vol if isinstance(vol, str) else (vol.get("source", "") if isinstance(vol, dict) else "")
            if "docker.sock" in str(source):
                findings.append((f"service:{name}", "внутрь контейнера смонтирован docker.sock"))
    return findings


def check_no_read_only(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("read_only") is not True:
            findings.append((f"service:{name}", "файловая система контейнера не переведена в режим read_only"))
    return findings


def check_missing_no_new_privileges(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        sec_opt = svc.get("security_opt") or []
        if not any("no-new-privileges" in str(opt) for opt in sec_opt):
            findings.append((f"service:{name}", "не установлена опция security_opt: no-new-privileges:true"))
    return findings


REGISTRY = {
    "C001": check_root_user,
    "C002": check_privileged,
    "C003": check_dangerous_capabilities,
    "C004": check_secrets_in_environment,
    "C005": check_exposed_sensitive_ports,
    "C006": check_latest_tag,
    "C007": check_host_network,
    "C008": check_docker_socket_mount,
    "C009": check_no_read_only,
    "C010": check_missing_no_new_privileges,
}
