"""Проверки docker-compose.yml.

Функции принимают распарсенный compose и возвращают
(location, detail, line) для каждого нарушения; line — строка объявления
сервиса или None, если она неизвестна. Severity/мера/remediation —
в rules/compose_rules.yaml, привязка по id через REGISTRY внизу файла.
"""

from __future__ import annotations

import re

from .base import CheckResult

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
ROOT_UIDS = {"root", "0"}


def _services(compose: dict) -> dict:
    return (compose or {}).get("services", {}) or {}


def _line(compose: dict, service: str) -> int | None:
    """Строка объявления сервиса, если compose разобран parse_compose."""
    service_line = getattr(compose, "service_line", None)
    return service_line(service) if service_line else None


def _is_root_user(value: object) -> bool:
    """True, если директива user явно указывает на root/uid 0.

    Принимает 'root', 'root:root', 0, '0:0' — во всех этих формах
    контейнер работает от root, и правило обязано сработать.
    """
    uid = str(value).strip().strip("\"'").split(":", 1)[0].strip().lower()
    return uid in ROOT_UIDS


def check_root_user(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        if "user" not in svc:
            findings.append(
                (
                    f"service:{name}",
                    "нет директивы 'user' — процесс в контейнере выполняется от root",
                    _line(compose, name),
                )
            )
        elif _is_root_user(svc["user"]):
            findings.append(
                (
                    f"service:{name}",
                    f"user: {svc['user']} — процесс в контейнере явно запущен от root",
                    _line(compose, name),
                )
            )
    return findings


def check_privileged(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("privileged") is True:
            findings.append(
                (f"service:{name}", "сервис запущен с privileged: true", _line(compose, name))
            )
    return findings


def check_dangerous_capabilities(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        caps = svc.get("cap_add") or []
        bad = [str(c) for c in caps if str(c).upper() in DANGEROUS_CAPS]
        if bad:
            findings.append(
                (
                    f"service:{name}",
                    f"добавлены опасные capabilities: {', '.join(bad)}",
                    _line(compose, name),
                )
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


def check_secrets_in_environment(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for key, value in _env_items(svc.get("environment")):
            if key.upper().endswith(("_FILE", "_FILENAME")):
                # docker secrets convention: значение — это путь, а не сам секрет
                continue
            if value and not value.startswith("$") and SECRET_KEY_RE.search(key):
                findings.append(
                    (
                        f"service:{name}",
                        f"переменная {key} содержит секрет в открытом виде",
                        _line(compose, name),
                    )
                )
    return findings


def _port_is_exposed(entry) -> tuple[bool, list[str]]:
    """Возвращает (публикуется_на_всех_интерфейсах, список container-портов).

    Портов может быть несколько: '5432-5433:5432-5433' — валидная запись
    диапазона, и каждый порт из него публикуется по-настоящему.
    """
    if isinstance(entry, dict):
        target = str(entry.get("target", ""))
        published = entry.get("published")
        if published in (None, ""):
            return False, _expand_ports(target)
        return entry.get("host_ip") not in SAFE_LOOPBACK, _expand_ports(target)

    text = str(entry)
    host_ip: str | None = None
    # IPv6-адрес хоста записывается в квадратных скобках: '[::1]:5432:5432'
    if text.startswith("["):
        closing = text.find("]")
        if closing != -1:
            host_ip = text[1:closing]
            text = text[closing + 1 :].lstrip(":")

    parts = text.split(":")
    if host_ip is None and len(parts) == 3:
        host_ip, _host_port, container_port = parts
    elif len(parts) >= 2:
        container_port = parts[-1]
    else:
        container_port = parts[0]
    container_port = container_port.split("/")[0]
    return host_ip not in SAFE_LOOPBACK, _expand_ports(container_port)


def _expand_ports(value: str) -> list[str]:
    """'5432' -> ['5432'], '5432-5434' -> ['5432', '5433', '5434']."""
    value = value.strip()
    if "-" not in value:
        return [value] if value else []
    start, _, end = value.partition("-")
    try:
        first, last = int(start), int(end)
    except ValueError:
        return [value]
    if last < first or last - first > 1024:  # защита от абсурдных диапазонов
        return [value]
    return [str(port) for port in range(first, last + 1)]


def _exposed_ports(svc: dict, watched: set[str]) -> list[tuple[object, str]]:
    hits = []
    for port_entry in svc.get("ports") or []:
        exposed, container_ports = _port_is_exposed(port_entry)
        if not exposed:
            continue
        for container_port in container_ports:
            if container_port in watched:
                hits.append((port_entry, container_port))
                break
    return hits


def check_exposed_sensitive_ports(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for port_entry, _container_port in _exposed_ports(svc, SENSITIVE_PORTS):
            findings.append(
                (
                    f"service:{name}",
                    f"порт {port_entry} публикуется на все интерфейсы хоста",
                    _line(compose, name),
                )
            )
    return findings


def check_latest_tag(compose: dict) -> list[CheckResult]:
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
                    _line(compose, name),
                )
            )
    return findings


def check_host_network(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("network_mode") == "host":
            findings.append(
                (f"service:{name}", "сервис использует network_mode: host", _line(compose, name))
            )
    return findings


def check_docker_socket_mount(compose: dict) -> list[CheckResult]:
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
                findings.append(
                    (
                        f"service:{name}",
                        "внутрь контейнера смонтирован docker.sock",
                        _line(compose, name),
                    )
                )
    return findings


def check_no_read_only(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("read_only") is not True:
            findings.append(
                (
                    f"service:{name}",
                    "файловая система контейнера не переведена в режим read_only",
                    _line(compose, name),
                )
            )
    return findings


def check_missing_no_new_privileges(compose: dict) -> list[CheckResult]:
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
                    _line(compose, name),
                )
            )
    return findings


def check_docker_api_exposed(compose: dict) -> list[CheckResult]:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for port_entry, _container_port in _exposed_ports(svc, DOCKER_API_PORTS):
            findings.append(
                (
                    f"service:{name}",
                    f"порт {port_entry} — незащищённый Docker Engine API, "
                    "доступ к нему эквивалентен root на хосте",
                    _line(compose, name),
                )
            )
    return findings


def check_missing_resource_limits(compose: dict) -> list[CheckResult]:
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
                    _line(compose, name),
                )
            )
    return findings


def check_missing_healthcheck(compose: dict) -> list[CheckResult]:
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
                    _line(compose, name),
                )
            )
    return findings


def check_debug_mode_enabled(compose: dict) -> list[CheckResult]:
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
                        _line(compose, name),
                    )
                )
    return findings


def check_sensitive_host_mount(compose: dict) -> list[CheckResult]:
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
                        _line(compose, name),
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
