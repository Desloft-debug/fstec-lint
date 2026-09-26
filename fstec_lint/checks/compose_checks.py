"""Проверки docker-compose.yml.

Каждая функция возвращает (location, detail, line) на нарушение.
Метаданные правил — в rules/compose_rules.yaml, связь по id в REGISTRY.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import wraps

from .base import CheckResult, CheckResults, as_list, is_root_user

SENSITIVE_PORTS = {"5432", "3306", "6379", "27017", "9200", "1433", "11211"}
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}
SAFE_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
DOCKER_API_PORTS = {"2375", "2376"}
# Системные каталоги хоста. Перечень совпадает с isOSDir из KICS: лишнее
# срабатывание на данных в /var или /srv дешевле пропущенного /etc.
SENSITIVE_HOST_MOUNTS = {
    "/",
    "/bin",
    "/boot",
    "/cdrom",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/selinux",
    "/srv",
    "/sys",
    "/usr",
    "/var",
}
DEBUG_KEY_RE = re.compile(r"DEBUG$", re.IGNORECASE)
DEBUG_TRUTHY = {"1", "true", "yes", "on"}
# ${DB_PASSWORD:-changeme}: значение по умолчанию лежит в репозитории.
ENV_DEFAULT_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:[-=]([^}]*)\}$")
# Значение целиком — подстановка: $VAR, ${VAR}, ${VAR:?err}.
# '$ecretPa55' подстановкой не считается.
ENV_SUBSTITUTION_RE = re.compile(r"^\$(?:\{[A-Za-z_][A-Za-z0-9_]*[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)$")


def _services(compose: dict) -> dict:
    return (compose or {}).get("services", {}) or {}


def _line(compose: dict, service: str, *keys: str) -> int | None:
    """Строка нарушающей директивы (самый ранний из ключей) или сервиса."""
    key_line = getattr(compose, "key_line", None)
    if callable(key_line):
        return key_line(service, *keys)
    service_line = getattr(compose, "service_line", None)
    return service_line(service) if service_line else None


def check_root_user(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        if "user" not in svc:
            findings.append(
                (
                    f"service:{name}",
                    "нет директивы 'user' — процесс в контейнере выполняется от root",
                    _line(compose, name, "user"),
                )
            )
        elif is_root_user(svc["user"]):
            findings.append(
                (
                    f"service:{name}",
                    f"user: {svc['user']} — процесс в контейнере явно запущен от root",
                    _line(compose, name, "user"),
                )
            )
    return findings


def check_privileged(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("privileged") is True:
            findings.append(
                (
                    f"service:{name}",
                    "сервис запущен с privileged: true",
                    _line(compose, name, "privileged"),
                )
            )
    return findings


def check_dangerous_capabilities(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        caps = as_list(svc.get("cap_add"))
        bad = [str(c) for c in caps if str(c).upper() in DANGEROUS_CAPS]
        dropped = {str(c).upper() for c in as_list(svc.get("cap_drop"))}
        problems = []
        if bad:
            problems.append(f"добавлены опасные capabilities: {', '.join(bad)}")
        if "ALL" not in dropped:
            problems.append(
                "не задан cap_drop: [ALL] — контейнер получает capabilities Docker по умолчанию"
            )
        if problems:
            findings.append(
                (
                    f"service:{name}",
                    "; ".join(problems),
                    _line(compose, name, "cap_add", "cap_drop"),
                )
            )
    return findings


def _env_items(env: object) -> list[tuple[str, str]]:
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


def check_secrets_in_environment(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for key, value in _env_items(svc.get("environment")):
            if key.upper().endswith(("_FILE", "_FILENAME")):
                # *_FILE по соглашению docker secrets содержит путь к файлу с секретом
                continue
            if not value or not SECRET_KEY_RE.search(key):
                continue
            default = ENV_DEFAULT_RE.match(value)
            if default is not None:
                if not default.group(1).strip():
                    continue
                detail = f"переменная {key} подставляет секрет по умолчанию: {value}"
            elif ENV_SUBSTITUTION_RE.match(value):
                # $VAR, ${VAR}: значение приходит извне.
                continue
            else:
                # '$$ecret' — экранированный литерал, а не подстановка.
                detail = f"переменная {key} содержит секрет в открытом виде"
            findings.append((f"service:{name}", detail, _line(compose, name, "environment")))
    return findings


def _port_is_exposed(entry: object) -> tuple[bool, list[str]]:
    """(публикуется ли на всех интерфейсах, порты контейнера).

    Диапазоны вида '5432-5433:5432-5433' раскрываются.
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
    for port_entry in as_list(svc.get("ports")):
        exposed, container_ports = _port_is_exposed(port_entry)
        if not exposed:
            continue
        for container_port in container_ports:
            if container_port in watched:
                hits.append((port_entry, container_port))
                break
    return hits


def check_exposed_sensitive_ports(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for port_entry, _container_port in _exposed_ports(svc, SENSITIVE_PORTS):
            findings.append(
                (
                    f"service:{name}",
                    f"порт {port_entry} публикуется на все интерфейсы хоста",
                    _line(compose, name, "ports"),
                )
            )
    return findings


def check_latest_tag(compose: dict) -> CheckResults:
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
                    _line(compose, name, "image"),
                )
            )
    return findings


def check_host_network(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("network_mode") == "host":
            findings.append(
                (
                    f"service:{name}",
                    "сервис использует network_mode: host",
                    _line(compose, name, "network_mode"),
                )
            )
    return findings


def check_docker_socket_mount(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for vol in as_list(svc.get("volumes")):
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
                        _line(compose, name, "volumes"),
                    )
                )
    return findings


def check_no_read_only(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and svc.get("read_only") is not True:
            findings.append(
                (
                    f"service:{name}",
                    "файловая система контейнера не переведена в режим read_only",
                    _line(compose, name, "read_only"),
                )
            )
    return findings


def _no_new_privileges_enabled(option: object) -> bool:
    """'no-new-privileges', ':true' или '=true'; ':false' опцию выключает."""
    text = str(option).strip().lower().replace("=", ":")
    if not text.startswith("no-new-privileges"):
        return False
    value = text[len("no-new-privileges") :].lstrip(":").strip()
    return value in ("", "true", "1")


def check_missing_no_new_privileges(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        sec_opt = as_list(svc.get("security_opt"))
        if not any(_no_new_privileges_enabled(opt) for opt in sec_opt):
            findings.append(
                (
                    f"service:{name}",
                    "не установлена опция security_opt: no-new-privileges:true",
                    _line(compose, name, "security_opt"),
                )
            )
    return findings


def check_docker_api_exposed(compose: dict) -> CheckResults:
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
                    _line(compose, name, "ports"),
                )
            )
    return findings


def check_missing_resource_limits(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        deploy = svc.get("deploy")
        resources = deploy.get("resources") if isinstance(deploy, dict) else None
        limits = resources.get("limits") if isinstance(resources, dict) else None
        limits = limits if isinstance(limits, dict) else {}
        missing = []
        if "mem_limit" not in svc and "memory" not in limits:
            missing.append("памяти (mem_limit или deploy.resources.limits.memory)")
        if not {"cpus", "cpu_quota"} & set(svc) and "cpus" not in limits:
            missing.append("CPU (cpus или deploy.resources.limits.cpus)")
        if missing:
            findings.append(
                (
                    f"service:{name}",
                    f"не задано ограничение {' и '.join(missing)} — "
                    "один контейнер может исчерпать ресурсы хоста",
                    _line(compose, name, "deploy", "mem_limit", "cpus"),
                )
            )
    return findings


def _healthcheck_disabled(healthcheck: object) -> bool:
    """disable: true или test: ["NONE"] отключают проверку, заданную в образе."""
    if not isinstance(healthcheck, dict):
        return False
    if healthcheck.get("disable"):
        return True
    test = healthcheck.get("test")
    first = test[0] if isinstance(test, list) and test else test
    return str(first).strip().upper() == "NONE"


def check_missing_healthcheck(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        healthcheck = svc.get("healthcheck")
        if not healthcheck or _healthcheck_disabled(healthcheck):
            findings.append(
                (
                    f"service:{name}",
                    "не задан healthcheck — отказ сервиса не будет обнаружен автоматически",
                    _line(compose, name, "healthcheck"),
                )
            )
    return findings


def check_debug_mode_enabled(compose: dict) -> CheckResults:
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
                        _line(compose, name, "environment"),
                    )
                )
    return findings


def _is_sensitive_host_path(path: str) -> bool:
    """Путь из SENSITIVE_HOST_MOUNTS или вложенный в него (/etc/ssl, /proc/1)."""
    if not path.startswith("/") or path.endswith("docker.sock"):
        return False  # docker.sock проверяет C008
    normalized = path.rstrip("/") or "/"
    if normalized == "/":
        return True
    return any(
        normalized == base or normalized.startswith(base + "/")
        for base in SENSITIVE_HOST_MOUNTS
        if base != "/"
    )


def _volume_host_paths(compose: dict) -> list[tuple[str, str]]:
    """(том, путь хоста) из driver_opts томов верхнего уровня: device, mountpoint."""
    volumes = (compose or {}).get("volumes") or {}
    if not isinstance(volumes, dict):
        return []
    found = []
    for name, spec in volumes.items():
        opts = spec.get("driver_opts") if isinstance(spec, dict) else None
        if not isinstance(opts, dict):
            continue
        for key in ("device", "mountpoint"):
            if opts.get(key):
                found.append((str(name), str(opts[key])))
    return found


def check_sensitive_host_mount(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for vol in as_list(svc.get("volumes")):
            if isinstance(vol, dict):
                source_path = str(vol.get("source", ""))
            elif ":" not in str(vol):
                continue  # '- /data' — анонимный том, каталог хоста не монтируется
            else:
                source_path = str(vol).split(":")[0]
            if _is_sensitive_host_path(source_path):
                findings.append(
                    (
                        f"service:{name}",
                        f"смонтирован чувствительный путь хоста '{source_path}' внутрь контейнера",
                        _line(compose, name, "volumes"),
                    )
                )
    # Том верхнего уровня, привязанный к каталогу хоста, опасен для любого
    # сервиса, который его подключит, поэтому находка относится к тому.
    volume_line = getattr(compose, "volume_line", None)
    for volume, path in _volume_host_paths(compose):
        if _is_sensitive_host_path(path):
            findings.append(
                (
                    f"volume:{volume}",
                    f"том {volume} привязан к чувствительному пути хоста '{path}'",
                    volume_line(volume) if callable(volume_line) else None,
                )
            )
    return findings


def check_flat_network(compose: dict) -> CheckResults:
    services = _services(compose)
    if len(services) < 2:
        return []
    if any(isinstance(svc, dict) and svc.get("networks") for svc in services.values()):
        return []
    return [
        (f"service:{name}", "сервис не подключён к именованной сети", _line(compose, name))
        for name, svc in services.items()
        if isinstance(svc, dict) and svc.get("network_mode") != "host"
    ]


# Драйверы, которые оставляют журнал на самом хосте.
LOCAL_LOG_DRIVERS = frozenset({"json-file", "local", "none"})


def check_logs_not_centralized(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        logging = svc.get("logging")
        driver = logging.get("driver") if isinstance(logging, dict) else None
        driver = str(driver or "json-file").strip().lower()
        if driver in LOCAL_LOG_DRIVERS:
            detail = (
                "logging.driver: none — журнал контейнера не ведётся"
                if driver == "none"
                else f"журнал контейнера остаётся на хосте (драйвер {driver})"
            )
            findings.append((f"service:{name}", detail, _line(compose, name, "logging")))
    return findings


ComposeCheck = Callable[[dict], CheckResults]


def _service_scope(check: ComposeCheck) -> ComposeCheck:
    """Добавляет строки для подавления: заголовок сервиса, директива, её элементы."""

    @wraps(check)
    def wrapped(compose: dict) -> CheckResults:
        suppression_lines = getattr(compose, "suppression_lines", None)
        results: list[CheckResult] = []
        for item in check(compose):
            location, detail, line = item[0], item[1], item[2]
            name = location.split("service:", 1)[-1]
            extra = suppression_lines(name, line) if callable(suppression_lines) else ()
            results.append((location, detail, line, tuple(extra)))
        return results

    return wrapped


REGISTRY = {
    "C001": _service_scope(check_root_user),
    "C002": _service_scope(check_privileged),
    "C003": _service_scope(check_dangerous_capabilities),
    "C004": _service_scope(check_secrets_in_environment),
    "C005": _service_scope(check_exposed_sensitive_ports),
    "C006": _service_scope(check_latest_tag),
    "C007": _service_scope(check_host_network),
    "C008": _service_scope(check_docker_socket_mount),
    "C009": _service_scope(check_no_read_only),
    "C010": _service_scope(check_missing_no_new_privileges),
    "C011": _service_scope(check_docker_api_exposed),
    "C012": _service_scope(check_missing_resource_limits),
    "C013": _service_scope(check_missing_healthcheck),
    "C014": _service_scope(check_debug_mode_enabled),
    "C015": _service_scope(check_sensitive_host_mount),
    "C016": _service_scope(check_flat_network),
    "C017": _service_scope(check_logs_not_centralized),
}
