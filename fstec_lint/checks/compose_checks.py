"""Проверки docker-compose.yml.

Функции принимают распарсенный compose и возвращают
(location, detail, line) для каждого нарушения; line — строка объявления
сервиса или None, если она неизвестна. Severity/мера/remediation —
в rules/compose_rules.yaml, привязка по id через REGISTRY внизу файла.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import wraps

from ..parsers.compose import MAX_YAML_DEPTH, MAX_YAML_EXPANDED_COST
from .base import CheckResult, CheckResults, as_list, is_root_user

SENSITIVE_PORTS = {"5432", "3306", "6379", "27017", "9200", "1433", "11211"}
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}
SAFE_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
DOCKER_API_PORTS = {"2375", "2376"}
SENSITIVE_HOST_MOUNTS = {"/etc", "/proc", "/sys", "/var/run", "/boot", "/root"}
DEBUG_KEY_RE = re.compile(r"DEBUG$", re.IGNORECASE)
DEBUG_TRUTHY = {"1", "true", "yes", "on"}
# ${DB_PASSWORD:-changeme} — подстановка со значением по умолчанию:
# сама ссылка безопасна, а вот дефолт в ней лежит в репозитории.
ENV_DEFAULT_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:?[\-+=]([^}]*)\}$")
# Подстановка compose целиком: $VAR, ${VAR}, ${VAR:?err} и т. п. Литерал,
# который просто начинается с '$' ('$ecretPa55'), подстановкой не является
# и обязан проверяться как секрет в открытом виде.
ENV_SUBSTITUTION_RE = re.compile(r"^\$(?:\{[A-Za-z_][A-Za-z0-9_]*[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)$")


def _guard_graph(root: object) -> None:
    """Bound direct API inputs before any check can format or traverse them."""
    completed: dict[int, tuple[int, int]] = {}
    active: set[int] = set()

    def visit(value: object, depth: int) -> tuple[int, int]:
        if depth > MAX_YAML_DEPTH:
            raise ValueError("Compose resource limit exceeded")
        if type(value) in (str, int, float, bool, type(None)):
            if type(value) is str:
                cost = 32 + 12 * len(value)
            elif type(value) is int:
                cost = 32 + 12 * (value.bit_length() + 1)
            else:
                cost = 64
            if cost > MAX_YAML_EXPANDED_COST:
                raise ValueError("Compose resource limit exceeded")
            return cost, 1
        if not isinstance(value, (dict, list)) or type(value) not in (dict, list) and depth != 1:
            raise ValueError("unsupported Compose shape")
        ident = id(value)
        if ident in active:
            raise ValueError("Compose resource limit exceeded")
        if ident in completed:
            cost, height = completed[ident]
            if depth + height - 1 > MAX_YAML_DEPTH:
                raise ValueError("Compose resource limit exceeded")
            return cost, height
        active.add(ident)
        cost, height = 32, 1
        children = (
            (item for pair in value.items() for item in pair)
            if isinstance(value, dict)
            else iter(value)
        )
        for child in children:
            child_cost, child_height = visit(child, depth + 1)
            cost += child_cost
            height = max(height, child_height + 1)
            if cost > MAX_YAML_EXPANDED_COST:
                raise ValueError("Compose resource limit exceeded")
        active.remove(ident)
        completed[ident] = cost, height
        return cost, height

    visit(root, 1)


def _scalar(value: object) -> bool:
    return type(value) in (str, int, float, bool, type(None))


def _services(compose: dict) -> dict:
    _guard_graph(compose)
    if not isinstance(compose, dict):
        raise ValueError("unsupported Compose shape")
    services = compose.get("services", {})
    if services is None:
        services = {}
    if not isinstance(services, dict):
        raise ValueError("unsupported Compose shape")
    for name, svc in services.items():
        if not _scalar(name) or not isinstance(svc, dict):
            raise ValueError("unsupported Compose shape")
        for field in ("user", "image"):
            value = svc.get(field)
            if not _scalar(value) or (
                field == "image" and value is not None and not isinstance(value, str)
            ):
                raise ValueError("unsupported Compose shape")
        env = svc.get("environment")
        if env is not None:
            if isinstance(env, dict):
                if any(not _scalar(k) or not _scalar(v) for k, v in env.items()):
                    raise ValueError("unsupported Compose shape")
            elif not isinstance(env, list) or any(not isinstance(item, str) for item in env):
                raise ValueError("unsupported Compose shape")
        for field in ("cap_add", "security_opt", "ports", "volumes"):
            value = svc.get(field)
            entries = value if isinstance(value, list) else ([] if value is None else [value])
            for item in entries:
                if isinstance(item, dict) and field in ("ports", "volumes"):
                    if field == "ports" and any(not _scalar(v) for v in item.values()):
                        raise ValueError("unsupported Compose shape")
                    if field == "volumes" and not _scalar(item.get("source")):
                        raise ValueError("unsupported Compose shape")
                elif not _scalar(item):
                    raise ValueError("unsupported Compose shape")
        deploy = svc.get("deploy")
        if isinstance(deploy, dict) and not isinstance(deploy.get("resources", {}), dict):
            raise ValueError("unsupported Compose shape")
    return services


def _line(compose: dict, service: str, *keys: str) -> int | None:
    """Строка нарушающей директивы сервиса, если compose разобран parse_compose.

    Находка привязывается к самому раннему из переданных ключей, а не к
    объявлению сервиса: иначе '# fstec-lint: ignore C005' над строкой
    'ports' не срабатывал, потому что находка числилась на 'db:'.
    """
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
        missing_drop = not any(str(c).upper() == "ALL" for c in as_list(svc.get("cap_drop")))
        if bad or missing_drop:
            detail = []
            if bad:
                detail.append(f"добавлены опасные capabilities: {', '.join(bad)}")
            if missing_drop:
                detail.append("cap_drop не содержит ALL")
            findings.append(
                (f"service:{name}", "; ".join(detail), _line(compose, name, "cap_add", "cap_drop"))
            )
    return findings


def _env_items(env: object) -> list[tuple[str, str]]:
    _guard_graph(env)
    items: list[tuple[str, str]] = []
    if isinstance(env, dict):
        for k, v in env.items():
            if not _scalar(k) or not _scalar(v):
                raise ValueError("unsupported Compose shape")
            items.append((str(k), "" if v is None else str(v)))
    elif isinstance(env, list):
        for entry in env:
            if not isinstance(entry, str):
                raise ValueError("unsupported Compose shape")
            if isinstance(entry, str) and "=" in entry:
                k, v = entry.split("=", 1)
                items.append((k, v))
    elif env is not None:
        raise ValueError("unsupported Compose shape")
    return items


def check_secrets_in_environment(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        for key, value in _env_items(svc.get("environment")):
            if key.upper().endswith(("_FILE", "_FILENAME")):
                # docker secrets convention: значение — это путь, а не сам секрет
                continue
            if not value or not SECRET_KEY_RE.search(key):
                continue
            default = ENV_DEFAULT_RE.match(value)
            if default is not None:
                if not default.group(1).strip():
                    continue
                detail = f"переменная {key} подставляет непустой секрет по умолчанию"
            elif ENV_SUBSTITUTION_RE.match(value):
                # Настоящая подстановка ($VAR, ${VAR}) — значение приходит
                # извне и в файле его нет.
                continue
            else:
                # '$$ecret' — экранированный литерал, а не подстановка.
                detail = f"переменная {key} содержит секрет в открытом виде"
            findings.append((f"service:{name}", detail, _line(compose, name, "environment")))
    return findings


def _port_is_exposed(entry: object) -> tuple[bool, list[str]]:
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


def check_missing_no_new_privileges(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        sec_opt = as_list(svc.get("security_opt"))
        enabled = any(
            re.fullmatch(r"no-new-privileges(?:\s*[:=]\s*(?:true|1))?", str(opt).strip(), re.I)
            for opt in sec_opt
        )
        if not enabled:
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
        resources = deploy.get("resources", {}) if isinstance(deploy, dict) else {}
        limits = resources.get("limits", {}) if isinstance(resources, dict) else {}
        limits = limits if isinstance(limits, dict) else {}

        def positive(value: object, memory: bool = False) -> bool:
            if isinstance(value, bool) or value is None:
                return False
            text = str(value).strip()
            pattern = (
                r"(?:[0-9]+(?:\.[0-9]+)?)(?:[kKmMgGtT](?:[bB])?)?"
                if memory
                else r"[0-9]+(?:\.[0-9]+)?"
            )
            if not re.fullmatch(pattern, text):
                return False
            number = re.match(r"[0-9]+(?:\.[0-9]+)?", text)
            return number is not None and float(number.group()) > 0

        cpu = (
            positive(svc.get("cpus"))
            or positive(svc.get("cpu_quota"))
            or positive(limits.get("cpus"))
        )
        memory = positive(svc.get("mem_limit"), True) or positive(limits.get("memory"), True)
        if not (cpu and memory):
            findings.append(
                (
                    f"service:{name}",
                    "неполные или некорректные ограничения ресурсов (mem_limit/cpus или "
                    "deploy.resources.limits) — один контейнер может исчерпать ресурсы хоста",
                    _line(compose, name, "deploy", "mem_limit", "cpus"),
                )
            )
    return findings


def check_missing_healthcheck(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        healthcheck = svc.get("healthcheck")
        test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
        disabled = isinstance(healthcheck, dict) and healthcheck.get("disable") is True
        none_test = (isinstance(test, list) and bool(test) and str(test[0]).upper() == "NONE") or (
            isinstance(test, str) and test.strip().upper() == "NONE"
        )
        if not healthcheck or disabled or none_test:
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
                label = key if SECRET_KEY_RE.search(key) else f"{key}={value}"
                findings.append(
                    (
                        f"service:{name}",
                        f"{label} — режим отладки включён, приложение может "
                        "раскрывать трассировки и внутренние данные",
                        _line(compose, name, "environment"),
                    )
                )
    return findings


def check_sensitive_host_mount(compose: dict) -> CheckResults:
    import posixpath

    findings: list[CheckResult] = []
    volumes = compose.get("volumes", {})
    volumes = volumes if isinstance(volumes, dict) else {}
    for name, svc in _services(compose).items():
        for vol in as_list(svc.get("volumes")):
            source = ""
            if isinstance(vol, dict):
                source = str(vol.get("source") or vol.get("src") or "")
                if vol.get("type") not in (None, "bind", "volume"):
                    continue
                if vol.get("type") != "bind" and not source.startswith("/"):
                    definition = volumes.get(source, {})
                    opts = definition.get("driver_opts", {}) if isinstance(definition, dict) else {}
                    source = (
                        str(opts.get("device") or opts.get("mountpoint") or "")
                        if isinstance(opts, dict)
                        else ""
                    )
            elif isinstance(vol, str) and ":" in vol:
                source = vol.split(":", 1)[0]
                definition = volumes.get(source, {})
                opts = definition.get("driver_opts", {}) if isinstance(definition, dict) else {}
                if isinstance(opts, dict) and (opts.get("device") or opts.get("mountpoint")):
                    source = str(opts.get("device") or opts.get("mountpoint"))
            if not source.startswith("/"):
                continue
            path = posixpath.normpath(source)
            if path == "/" or any(
                path == root or path.startswith(root + "/") for root in SENSITIVE_HOST_MOUNTS
            ):
                findings.append(
                    (
                        f"service:{name}",
                        "смонтирован чувствительный путь хоста",
                        _line(compose, name, "volumes"),
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


def check_logs_not_centralized(compose: dict) -> CheckResults:
    findings: list[CheckResult] = []
    for name, svc in _services(compose).items():
        logging = svc.get("logging")
        driver = logging.get("driver") if isinstance(logging, dict) else None
        if driver is None or str(driver).strip().lower() in {"json-file", "local", "none"}:
            findings.append(
                (
                    f"service:{name}",
                    "централизованный сбор не указан в Compose; "
                    "настройки демона и внешние сборщики не проверены",
                    _line(compose, name, "logging"),
                )
            )
    return findings


ComposeCheck = Callable[[dict], CheckResults]


def _service_scope(check: ComposeCheck) -> ComposeCheck:
    """Прикладывает к находке строки, на которых её можно подавить.

    Комментарий пишут в трёх местах: на заголовке сервиса, у директивы и
    у конкретного элемента внутри неё. Работать должны все три.
    """

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
    "C017": _service_scope(check_logs_not_centralized),
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
}
