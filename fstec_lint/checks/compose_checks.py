"""Проверки docker-compose.yml.

Функции принимают распарсенный compose-словарь и возвращают
(location, detail) для каждого нарушения. Severity/мера/remediation —
в rules/compose_rules.yaml, привязка по id через REGISTRY внизу файла.
"""

from __future__ import annotations

import re

SENSITIVE_PORTS = {"5432", "3306", "6379", "27017", "9200", "1433", "11211"}
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}
SAFE_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
DOCKER_API_PORTS = {"2375", "2376"}
SENSITIVE_HOST_MOUNTS = {"/", "/etc", "/proc", "/sys", "/var/run", "/boot", "/root"}
DEBUG_KEY_RE = re.compile(r"DEBUG$", re.IGNORECASE)
DEBUG_TRUTHY = {"1", "true", "yes", "on"}


def _services(compose: dict) -> dict:
    return (compose or {}).get("services", {}) or {}


def check_root_user(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        if "user" not in svc:
            findings.append(
                (
                    f"service:{name}",
                    "нет директивы 'user' — процесс в контейнере выполняется от root",
                )
            )
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
            findings.append(
                (f"service:{name}", f"добавлены опасные capabilities: {', '.join(bad)}")
            )
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
                findings.append(
                    (
                        f"service:{name}",
                        f"переменная {key} содержит секрет в открытом виде",
                    )
                )
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
                findings.append(
                    (
                        f"service:{name}",
                        f"порт {port_entry} публикуется на все интерфейсы хоста",
                    )
                )
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
            findings.append(
                (
                    f"service:{name}",
                    f"образ '{image}' использует тег :latest либо не закреплён по версии/digest",
                )
            )
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
            source = (
                vol
                if isinstance(vol, str)
                else (vol.get("source", "") if isinstance(vol, dict) else "")
            )
            if "docker.sock" in str(source):
                findings.append((f"service:{name}", "внутрь контейнера смонтирован docker.sock"))
    return findings


def check_no_read_only(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("read_only") is not True:
            findings.append(
                (
                    f"service:{name}",
                    "файловая система контейнера не переведена в режим read_only",
                )
            )
    return findings


def check_missing_no_new_privileges(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        sec_opt = svc.get("security_opt") or []
        if not any("no-new-privileges" in str(opt) for opt in sec_opt):
            findings.append(
                (
                    f"service:{name}",
                    "не установлена опция security_opt: no-new-privileges:true",
                )
            )
    return findings


def check_docker_api_exposed(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for port_entry in svc.get("ports") or []:
            exposed, container_port = _port_is_exposed(port_entry)
            if exposed and container_port in DOCKER_API_PORTS:
                findings.append(
                    (
                        f"service:{name}",
                        f"порт {port_entry} — незащищённый Docker Engine API, "
                        "доступ к нему эквивалентен root на хосте",
                    )
                )
    return findings


def check_missing_resource_limits(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        has_legacy_limits = "mem_limit" in svc or "cpus" in svc
        deploy = svc.get("deploy")
        has_deploy_limits = bool(
            isinstance(deploy, dict) and (deploy.get("resources") or {}).get("limits")
        )
        if not has_legacy_limits and not has_deploy_limits:
            findings.append(
                (
                    f"service:{name}",
                    "не заданы ограничения ресурсов (mem_limit/cpus или "
                    "deploy.resources.limits) — один контейнер может исчерпать ресурсы хоста",
                )
            )
    return findings


def check_missing_healthcheck(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        healthcheck = svc.get("healthcheck")
        if not healthcheck or (isinstance(healthcheck, dict) and healthcheck.get("disable")):
            findings.append(
                (
                    f"service:{name}",
                    "не задан healthcheck — отказ сервиса не будет обнаружен автоматически",
                )
            )
    return findings


def check_debug_mode_enabled(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for key, value in _env_items(svc.get("environment")):
            if DEBUG_KEY_RE.search(key) and value.strip().lower() in DEBUG_TRUTHY:
                findings.append(
                    (
                        f"service:{name}",
                        f"{key}={value} — режим отладки включён, приложение может "
                        "раскрывать трассировки и внутренние данные",
                    )
                )
    return findings


def check_sensitive_host_mount(compose: dict) -> list[tuple[str, str]]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for vol in svc.get("volumes") or []:
            if isinstance(vol, dict):
                source_path = str(vol.get("source", ""))
            else:
                source_path = str(vol).split(":")[0]
            if source_path in SENSITIVE_HOST_MOUNTS:
                findings.append(
                    (
                        f"service:{name}",
                        f"смонтирован чувствительный путь хоста '{source_path}' внутрь контейнера",
                    )
                )
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
    "C011": check_docker_api_exposed,
    "C012": check_missing_resource_limits,
    "C013": check_missing_healthcheck,
    "C014": check_debug_mode_enabled,
    "C015": check_sensitive_host_mount,
}
