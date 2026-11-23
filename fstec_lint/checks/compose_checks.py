"""Проверки docker-compose.yml.

Функции принимают распарсенный compose и возвращают
(location, detail, line) для каждого нарушения; line — строка объявления
сервиса или None, если она неизвестна. Severity/мера/remediation —
в rules/compose_rules.yaml, привязка по id через REGISTRY внизу файла.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from functools import wraps
from ipaddress import IPv6Address, ip_address

from ..parsers.compose import MAX_YAML_DEPTH, MAX_YAML_EXPANDED_COST
from .base import CheckResult, CheckResults, as_list, is_root_user

SENSITIVE_PORTS = {"5432", "3306", "6379", "27017", "9200", "1433", "11211"}
SECRET_KEY_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"}
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


_INTERPOLATION = re.compile(r"\$\$|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*)")


def _is_dynamic(value: object) -> bool:
    """A Compose variable reference (including mixed strings), not an escaped dollar."""
    return isinstance(value, str) and any(
        match.group() != "$$" for match in _INTERPOLATION.finditer(value)
    )


def _any_dynamic(value: object) -> bool:
    if isinstance(value, (list, dict)):
        entries = value.values() if isinstance(value, dict) else value
        return any(_is_dynamic(entry) for entry in entries)
    return _is_dynamic(value)


def _compose_boolean(value: object) -> bool | None:
    """Match compose-go toBoolean literals; leave interpolation unresolved."""
    if value is None or type(value) is bool:
        return value
    if isinstance(value, str):
        if _is_dynamic(value):
            return None
        lowered = value.lower()
        if lowered in {"true", "y", "yes", "on"}:
            return True
        if lowered in {"false", "n", "no", "off"}:
            return False
    raise ValueError("unsupported Compose boolean")


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
        # Validate supported boolean spellings without resolving environment.
        for field in ("privileged", "read_only"):
            _compose_boolean(svc.get(field))
        healthcheck = svc.get("healthcheck")
        if healthcheck is not None:
            if not isinstance(healthcheck, dict):
                raise ValueError("unsupported Compose shape")
            _compose_boolean(healthcheck.get("disable"))
            test = healthcheck.get("test")
            if (
                test is not None
                and not isinstance(test, str)
                and not (isinstance(test, list) and all(isinstance(item, str) for item in test))
            ):
                raise ValueError("unsupported Compose healthcheck test")
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


def validate_compose_shape(compose: dict) -> None:
    """Preflight the shared rule input once; direct checks retain their guards."""
    _services(compose)


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


def _entry_line(compose: dict, service: str, field: str, entry: str | int) -> int | None:
    entry_line = getattr(compose, "entry_line", None)
    return (
        entry_line(service, field, entry)
        if callable(entry_line)
        else _line(compose, service, field)
    )


def check_root_user(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        user = svc.get("user")
        if user is None or user == "":
            findings.append(
                (
                    f"service:{name}",
                    "пользователь не задан в Compose; используется настройка образа, "
                    "которая этим правилом не проверяется",
                    _line(compose, name, "user"),
                )
            )
        elif not _is_dynamic(user) and is_root_user(user):
            findings.append(
                (
                    f"service:{name}",
                    "в Compose явно указан root/uid 0; состояние контейнера не проверено",
                    _line(compose, name, "user"),
                )
            )
    return findings


def check_privileged(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if isinstance(svc, dict) and _compose_boolean(svc.get("privileged")) is True:
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
        bad = [str(c) for c in caps if str(c).upper().removeprefix("CAP_") in DANGEROUS_CAPS]
        if bad:
            findings.append(
                (
                    f"service:{name}",
                    f"явно добавлены привилегии: {', '.join(bad)}",
                    _line(compose, name, "cap_add"),
                )
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
            findings.append(
                (f"service:{name}", detail, _entry_line(compose, name, "environment", key))
            )
    return findings


def _bind_scope(raw: object) -> str:
    if raw in (None, ""):
        return "default"
    host = str(raw).strip().removeprefix("[").removesuffix("]")
    if host.lower() == "localhost":  # preserve the offline loopback interpretation
        return "loopback"
    try:
        address = ip_address(host)
    except ValueError:
        return "unknown"
    if address.is_unspecified:
        return "wildcard4" if address.version == 4 else "wildcard6"
    mapped = address.ipv4_mapped if isinstance(address, IPv6Address) else None
    if address.is_loopback or (mapped is not None and mapped.is_loopback):
        return "loopback"
    return "explicit"


def _port_entry(entry: object) -> tuple[str, str, str] | None:
    # The presence of an entry under 'ports', even without a fixed host
    # port, means publication. The optional 'published' selects that port.
    if isinstance(entry, dict):
        scope = _bind_scope(entry.get("host_ip"))
        target = str(entry.get("target") or "")
        protocol = str(entry.get("protocol") or "tcp")
    elif isinstance(entry, (str, int)) and not isinstance(entry, bool):
        text = str(entry)
        if _is_dynamic(text):
            return None  # A variable may also contribute separators.
        host: str | None = None
        if text.startswith("["):
            closing = text.find("]:")
            if closing < 0:
                return None
            host = text[1:closing]
            text = text[closing + 2 :]
        parts = text.rsplit(":", 2)
        if host is None and len(parts) == 3:
            host = parts[0]
        target, _, protocol = parts[-1].partition("/")
        scope = _bind_scope(host)
        protocol = protocol or "tcp"
    else:
        return None
    if re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", target) is None:
        return None
    return scope, target, protocol.lower()


_BIND_WORDING = {
    "default": "публикуется без явного адреса привязки",
    "wildcard4": "публикуется на всех интерфейсах IPv4",
    "wildcard6": "публикуется на всех интерфейсах IPv6",
    "explicit": "публикуется на явно заданном адресе вне loopback",
}


def _exposed_ports(
    svc: dict, watched: set[str], *, tcp_only: bool = False
) -> list[tuple[str, str, int]]:
    hits = []
    for index, entry in enumerate(as_list(svc.get("ports"))):
        binding = _port_entry(entry)
        if binding is None:
            continue
        scope, target, protocol = binding
        if scope not in _BIND_WORDING or (tcp_only and protocol != "tcp"):
            continue
        first, _, last = target.partition("-")
        start, end = int(first), int(last or first)
        if not (1 <= start <= end <= 65535):
            continue
        hit = next((port for port in sorted(watched, key=int) if start <= int(port) <= end), None)
        if hit is not None:
            hits.append((hit, scope, index))
    return hits


def check_exposed_sensitive_ports(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        for port, scope, index in _exposed_ports(svc, SENSITIVE_PORTS):
            findings.append(
                (
                    f"service:{name}",
                    f"порт контейнера {port} {_BIND_WORDING[scope]}; "
                    "достижимость по сети не подтверждена",
                    _entry_line(compose, name, "ports", index),
                )
            )
    return findings


def check_latest_tag(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if not isinstance(svc, dict):
            continue
        image = svc.get("image")
        if not image or _is_dynamic(image):
            continue
        if "@sha256:" in image:
            continue
        last_segment = image.split("/")[-1]
        if ":" not in last_segment or last_segment.endswith(":latest"):
            findings.append(
                (
                    f"service:{name}",
                    "для образа указан тег latest либо отсутствует явный тег или digest",
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
            if isinstance(vol, str) and ":" in vol:
                source = vol.split(":", 1)[0]
                if not source.startswith(("/", ".", "~")):
                    continue  # Named volume, not a host bind source.
            elif isinstance(vol, dict) and vol.get("type") == "bind":
                source = str(vol.get("source") or "")
            else:
                continue
            if posixpath.basename(source.rstrip("/")) == "docker.sock":
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
        if (
            isinstance(svc, dict)
            and not _is_dynamic(svc.get("read_only"))
            and _compose_boolean(svc.get("read_only")) is not True
        ):
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
        if not enabled and not _any_dynamic(sec_opt):
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
        for container_port, scope, index in _exposed_ports(svc, DOCKER_API_PORTS, tcp_only=True):
            findings.append(
                (
                    f"service:{name}",
                    f"типовой TCP-порт Docker API ({container_port}) {_BIND_WORDING[scope]}; "
                    "сервис, TLS и аутентификация не подтверждены",
                    _entry_line(compose, name, "ports", index),
                )
            )
    return findings


def _positive_limit(value: object, *, memory: bool = False) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    text = str(value).strip()
    pattern = (
        r"(?:[0-9]+(?:\.[0-9]+)?)(?:[kKmMgGtT](?:[bB])?)?" if memory else r"[0-9]+(?:\.[0-9]+)?"
    )
    if not re.fullmatch(pattern, text):
        return False
    number = re.match(r"[0-9]+(?:\.[0-9]+)?", text)
    return number is not None and float(number.group()) > 0


def _limit_state(values: tuple[object, ...], *, memory: bool = False) -> str:
    if any(_positive_limit(value, memory=memory) for value in values):
        return "set"
    return "unknown" if any(_is_dynamic(value) for value in values) else "missing"


def _resource_limit_states(svc: dict) -> tuple[str, str]:
    deploy = svc.get("deploy")
    resources = deploy.get("resources", {}) if isinstance(deploy, dict) else {}
    limits = resources.get("limits", {}) if isinstance(resources, dict) else {}
    limits = limits if isinstance(limits, dict) else {}
    return (
        _limit_state((svc.get("cpus"), svc.get("cpu_quota"), limits.get("cpus"))),
        _limit_state((svc.get("mem_limit"), limits.get("memory")), memory=True),
    )


def check_missing_resource_limits(compose: dict) -> CheckResults:
    findings = []
    for name, svc in _services(compose).items():
        if "missing" in _resource_limit_states(svc):
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
        disabled = (
            isinstance(healthcheck, dict) and _compose_boolean(healthcheck.get("disable")) is True
        )
        none_test = (isinstance(test, list) and bool(test) and str(test[0]).upper() == "NONE") or (
            isinstance(test, str) and test.strip().upper() == "NONE"
        )
        if not healthcheck or disabled or none_test:
            findings.append(
                (
                    f"service:{name}",
                    "не задан healthcheck — отказ сервиса не будет обнаружен автоматически",
                    _entry_line(compose, name, "healthcheck", "disable" if disabled else "test"),
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
                        _entry_line(compose, name, "environment", key),
                    )
                )
    return findings


def check_sensitive_host_mount(compose: dict) -> CheckResults:
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
    sharing_default = []
    for name, svc in _services(compose).items():
        if svc.get("network_mode"):
            continue
        networks = svc.get("networks")
        if not networks or isinstance(networks, (list, dict)) and "default" in networks:
            sharing_default.append(name)
    if len(sharing_default) < 2:
        return []
    return [
        (
            f"service:{name}",
            "сервис делит сеть default с другими сервисами Compose; "
            "обоснованность разделения и внешний доступ не проверены",
            _line(compose, name, "networks"),
        )
        for name in sharing_default
    ]


def _check_host_namespace(compose: dict, field: str) -> CheckResults:
    return [
        (
            f"service:{name}",
            f"{field}: host использует пространство имён хоста",
            _line(compose, name, field),
        )
        for name, svc in _services(compose).items()
        if svc.get(field) == "host"
    ]


def check_host_pid(compose: dict) -> CheckResults:
    return _check_host_namespace(compose, "pid")


def check_host_ipc(compose: dict) -> CheckResults:
    return _check_host_namespace(compose, "ipc")


def check_api_socket_delegation(compose: dict) -> CheckResults:
    return [
        (
            f"service:{name}",
            "use_api_socket делегирует сервису доступ к API Docker",
            _line(compose, name, "use_api_socket"),
        )
        for name, svc in _services(compose).items()
        if _compose_boolean(svc.get("use_api_socket")) is True
    ]


_HISTORY_FIELDS = {
    "C001": "user",
    "C002": "privileged",
    "C006": "image",
    "C007": "network_mode",
    "C009": "read_only",
    "C020": "use_api_socket",
}


def _watch_dynamic_ports(svc: dict, rule_id: str) -> bool:
    watched = SENSITIVE_PORTS if rule_id == "C005" else DOCKER_API_PORTS
    for entry in as_list(svc.get("ports")):
        if isinstance(entry, dict):
            if _bind_scope(entry.get("host_ip")) == "loopback":
                continue
            proto = entry.get("protocol")
            if (
                rule_id == "C011"
                and proto
                and not _is_dynamic(proto)
                and str(proto).lower() != "tcp"
            ):
                continue
            if _is_dynamic(entry.get("target")):
                return True
            binding = _port_entry(entry)
            if binding is None:
                continue
            scope, target, _ = binding
            first, _, last = target.partition("-")
            if any(int(first) <= int(port) <= int(last or first) for port in watched) and (
                scope == "unknown" or rule_id == "C011" and _is_dynamic(proto)
            ):
                return True
        elif _is_dynamic(entry):
            # A short-form variable may contribute a target or bind/address separators.
            return True
        else:
            binding = _port_entry(entry)
            if binding is not None and binding[0] == "unknown":
                first, _, last = binding[1].partition("-")
                if any(int(first) <= int(port) <= int(last or first) for port in watched) and (
                    rule_id == "C005" or binding[2] == "tcp"
                ):
                    return True
    return False


def _watch_dynamic_volume(svc: dict, compose: dict, rule_id: str) -> bool:
    volumes = compose.get("volumes")
    for entry in as_list(svc.get("volumes")):
        if isinstance(entry, dict):
            kind = entry.get("type")
            source = entry.get("source") or (entry.get("src") if rule_id == "C015" else None)
        elif isinstance(entry, str):
            if ":" not in entry:
                if _is_dynamic(entry):
                    return True
                continue
            kind = None
            source = entry.split(":", 1)[0]
        else:
            continue
        if rule_id == "C008":
            if isinstance(entry, dict) and kind != "bind" and not _is_dynamic(kind):
                continue
            if _is_dynamic(source) or (
                _is_dynamic(kind)
                and isinstance(source, str)
                and posixpath.basename(source.rstrip("/")) == "docker.sock"
            ):
                return True
            continue
        if kind not in (None, "bind", "volume") and not _is_dynamic(kind):
            continue
        if _is_dynamic(source) or (_is_dynamic(kind) and bool(source)):
            return True
        if (
            rule_id == "C015"
            and kind != "bind"
            and isinstance(volumes, dict)
            and isinstance(source, str)
        ):
            definition = volumes.get(source)
            opts = definition.get("driver_opts") if isinstance(definition, dict) else None
            if isinstance(opts, dict) and _is_dynamic(opts.get("device") or opts.get("mountpoint")):
                return True
    return False


def _watch_dynamic_env(svc: dict, rule_id: str) -> bool:
    env = svc.get("environment")
    if isinstance(env, list):
        for entry in env:
            key, equal, value = entry.partition("=")
            if _is_dynamic(key) and (equal or rule_id == "C014"):
                return True
            if rule_id == "C014" and DEBUG_KEY_RE.search(key) and (not equal or _is_dynamic(value)):
                return True
    elif isinstance(env, dict) and rule_id == "C014":
        return any(
            DEBUG_KEY_RE.search(str(key)) and (value is None or _is_dynamic(value))
            for key, value in env.items()
        )
    return False


def _unresolved_service(compose: dict, svc: dict, rule_id: str) -> bool:
    if rule_id in _HISTORY_FIELDS:
        return _is_dynamic(svc.get(_HISTORY_FIELDS[rule_id]))
    if rule_id in {"C018", "C019"}:
        value = svc.get("pid" if rule_id == "C018" else "ipc")
        return value is not None and (
            not isinstance(value, str) or _is_dynamic(value) or ":" in value
        )
    if rule_id == "C003":
        return _any_dynamic(svc.get("cap_add"))
    if rule_id in {"C004", "C014"}:
        return _watch_dynamic_env(svc, rule_id)
    if rule_id in {"C005", "C011"}:
        return _watch_dynamic_ports(svc, rule_id)
    if rule_id in {"C008", "C015"}:
        return _watch_dynamic_volume(svc, compose, rule_id)
    if rule_id == "C010":
        return _any_dynamic(svc.get("security_opt"))
    if rule_id == "C012":
        states = _resource_limit_states(svc)
        return "unknown" in states and "missing" not in states
    if rule_id == "C013":
        healthcheck = svc.get("healthcheck")
        if not isinstance(healthcheck, dict):
            return False
        disabled = _compose_boolean(healthcheck.get("disable"))
        test = healthcheck.get("test")
        operator = test[0] if isinstance(test, list) and test else test
        if disabled is True or isinstance(operator, str) and operator.strip().upper() == "NONE":
            return False
        return _is_dynamic(healthcheck.get("disable")) or _is_dynamic(operator)
    if rule_id == "C016":
        networks = svc.get("networks")
        # Compose does not interpolate mapping keys.
        return _is_dynamic(svc.get("network_mode")) or (
            isinstance(networks, list) and _any_dynamic(networks)
        )
    if rule_id == "C017":
        logging = svc.get("logging")
        return isinstance(logging, dict) and _is_dynamic(logging.get("driver"))
    return False


def unresolved_services(compose: dict, rule_id: str) -> tuple[str, ...]:
    """Names of services whose rule-relevant inputs cannot be resolved offline.

    The engine already validates shared shape. No reads of project or host
    environment happen here; a literal default is not the effective value
    when a setting can be overridden.
    """
    services = compose.get("services") or {}
    return tuple(
        str(name) for name, svc in services.items() if _unresolved_service(compose, svc, rule_id)
    )


def has_unresolved_history_value(compose: dict, rule_id: str) -> bool:
    return bool(unresolved_services(compose, rule_id))


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
    "C018": _service_scope(check_host_pid),
    "C019": _service_scope(check_host_ipc),
    "C020": _service_scope(check_api_socket_delegation),
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
