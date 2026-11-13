from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from .checks import (
    compose_checks,
    dockerfile_checks,
    dotenv_checks,
    linux_checks,
    nginx_checks,
    postfix_checks,
    postgres_checks,
    sshd_checks,
    systemd_checks,
)
from .checks.base import CheckResult, CheckResults
from .models import Finding, Rule, Severity
from .parsers.base import BoundedReader, SourceLine
from .parsers.compose import (
    MAX_FILE_BYTES,
    _BoundedLoader,
    _guard_graph,
    _guard_merges,
    parse_compose,
)
from .parsers.dockerfile import parse_dockerfile
from .parsers.dotenv import EnvFile, parse_dotenv
from .parsers.linux import parse_login_defs, parse_pwquality, parse_rsyslog, parse_useradd_defaults
from .parsers.nginx import NginxConfig, parse_nginx
from .parsers.postfix import parse_postfix_main
from .parsers.postgres import PostgreSQLConfig, parse_pg_hba, parse_postgresql_conf
from .parsers.sshd import parse_sshd_config
from .parsers.systemd import parse_systemd_unit
from .pdn import in_base_set

RULES_DIR = Path(__file__).parent / "rules"

COMPOSE_FILE_PATTERNS = (
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose.yml",
    "compose.yaml",
    "compose.override.yml",
    "compose.override.yaml",
)
POSTGRESQL_CONF_PATTERNS = ("postgresql.conf",)
PG_HBA_PATTERNS = ("pg_hba.conf",)
SSHD_CONFIG_PATTERNS = ("sshd_config",)
SYSTEMD_UNIT_PATTERNS = ("*.service",)
DOCKERFILE_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.dockerfile")

# Каталоги со сторонним и служебным содержимым: конфиги внутри них не
# наши и правятся не нами, а на большом репозитории они дают основную
# массу шума и времени обхода.
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".agent-runs",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
    }
)

PRODUCTION_EXCLUDED_DIRS = frozenset(
    {"test", "tests", "fixture", "fixtures", "example", "examples", "demo", "demos"}
)

CheckFn = Callable[[Any], CheckResults]

# Подавление находки прямо в проверяемом файле: комментарий действует на
# свою строку и на следующую, чтобы его можно было писать и в хвосте
# строки, и над ней (в YAML хвост не всегда читаем).
#   ports: ["5432:5432"]  # fstec-lint: ignore C005
#   # fstec-lint: ignore
SUPPRESSION_RE = re.compile(r"fstec-lint:\s*ignore(?P<rules>[A-Za-z0-9,*\s]*)", re.IGNORECASE)


@dataclass(frozen=True)
class ScanError:
    """Файл, который не удалось разобрать: битый синтаксис, не UTF-8, нет прав."""

    file: str
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    suppressed: int = 0


class RulesError(ValueError):
    """Безопасная диагностика некорректного набора правил."""


def load_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    rules: list[Rule] = []
    try:
        rule_files = sorted(p for p in rules_dir.iterdir() if p.match("*.yaml"))
    except OSError:
        raise RulesError("не удалось прочитать каталог правил") from None
    for yaml_file in rule_files:
        try:
            with yaml_file.open("rb") as source:
                content = source.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                raise ValueError("rules YAML resource limit exceeded")
            loader = _BoundedLoader(content.decode("utf-8"))
            try:
                node = loader.get_single_node()
                _guard_graph(node)
                _guard_merges(node)
                raw = loader.construct_document(node) if node is not None else []
            finally:
                loader.dispose()
        except Exception:
            raise RulesError("недопустимый YAML правил или превышен лимит") from None
        if not isinstance(raw, list):
            raise RulesError("набор правил должен быть списком")
        for index, item in enumerate(raw, 1):
            required = (
                "id",
                "title",
                "severity",
                "measure",
                "description",
                "remediation",
                "target",
            )
            optional = (
                "measure_title",
                "orders",
                "submeasure",
                "submeasure_title",
                "activity",
                "activity_title",
                "cwe",
                "weakness_type",
                "pdn_measure",
                "pdn_measure_title",
            )
            if not isinstance(item, dict):
                raise RulesError(f"правила: запись {index} должна быть объектом")
            for key in required:
                if not isinstance(item.get(key), str):
                    raise RulesError(f"правила: запись {index}, недопустимое поле {key}")
            for key in optional:
                if key in item and not isinstance(item[key], str):
                    raise RulesError(f"правила: запись {index}, недопустимое поле {key}")
            try:
                severity = Severity.from_str(item["severity"])
            except ValueError:
                raise RulesError(f"правила: запись {index}, недопустимое поле severity") from None
            rules.append(
                Rule(
                    id=item["id"],
                    title=item["title"],
                    severity=severity,
                    measure=item["measure"],
                    measure_title=item.get("measure_title", ""),
                    description=" ".join(item["description"].split()),
                    remediation=" ".join(item["remediation"].split()),
                    target=item["target"],
                    orders=item.get("orders", ""),
                    submeasure=item.get("submeasure", ""),
                    submeasure_title=item.get("submeasure_title", ""),
                    activity=item.get("activity", ""),
                    activity_title=item.get("activity_title", ""),
                    cwe=item.get("cwe", ""),
                    weakness_type=item.get("weakness_type", ""),
                    pdn_measure=item.get("pdn_measure", ""),
                    pdn_measure_title=item.get("pdn_measure_title", ""),
                )
            )
    return rules


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _matches_rule(rule_id: str, patterns: Iterable[str]) -> bool:
    """Правило задаётся id или glob-ом: C001, C*, ?00*. Регистр не важен."""
    return any(fnmatch.fnmatch(rule_id.upper(), pattern.upper()) for pattern in patterns)


def filter_rules(
    rules: list[Rule], select: Sequence[str] = (), ignore: Sequence[str] = ()
) -> list[Rule]:
    """Оставляет правила из --select (если он задан) минус правила из --ignore."""
    if select:
        rules = [rule for rule in rules if _matches_rule(rule.id, select)]
    if ignore:
        rules = [rule for rule in rules if not _matches_rule(rule.id, ignore)]
    return rules


def filter_by_uz(rules: list[Rule], level: int | None) -> list[Rule]:
    """Правила, чья мера входит в базовый набор для уровня УЗ.

    Наборы заданы приложением к приказу N 21. Мера вне набора применяется
    при адаптации (пункты 9 и 10), так что фильтр только сужает проверку.
    """
    if level is None:
        return rules
    return [rule for rule in rules if in_base_set(rule.pdn_measure, level)]


def unknown_patterns(rules: list[Rule], patterns: Sequence[str]) -> list[str]:
    """Шаблоны, не подошедшие ни к одному правилу, — обычно это опечатка."""
    return [p for p in patterns if not any(_matches_rule(rule.id, [p]) for rule in rules)]


def inline_suppressions(
    path: Path, *, comment_offsets: Mapping[int, int] | None = None, scan_root: Path | None = None
) -> dict[int, set[str]]:
    """{строка: набор правил} из комментариев в самом файле.

    Пустой набор означает «подавить любое правило на этой строке».
    Комментарий действует на свою строку и на следующую.
    """
    # Parsers that know the grammar may supply zero-based offsets of actual
    # comment markers, keyed by one-based physical line number. Without them,
    # retain the existing behavior for currently supported formats.
    data = BoundedReader(scan_root or path.parent).read(path).encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("suppression resource limit exceeded")
    text = data.decode("utf-8")

    suppressions: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        if comment_offsets is not None:
            offset = comment_offsets.get(lineno)
            if offset is None:
                continue
            if offset < 0 or offset >= len(line) or line[offset] != "#":
                raise ValueError("invalid comment offset")
            line = line[offset:]
        match = SUPPRESSION_RE.search(line)
        if match is None:
            continue
        raw = match.group("rules").replace(",", " ").split()
        rules = {token.upper() for token in raw}
        for target in (lineno, lineno + 1):
            if not rules:
                # Сплошное подавление поглощает любой перечень правил...
                suppressions[target] = set()
                continue
            already = suppressions.get(target)
            if already is not None and not already:
                # ...и обратно им не сужается: комментарий '# fstec-lint:
                # ignore' на строке выше глушит строку целиком, даже если
                # на ней самой перечислены отдельные правила.
                continue
            suppressions.setdefault(target, set()).update(rules)
    return suppressions


def _is_suppressed(finding: Finding, suppressions: dict[int, set[str]]) -> bool:
    """Подавлена ли находка комментарием в самом файле."""
    for lineno in (finding.line, *finding.suppress_lines):
        if lineno is None or lineno not in suppressions:
            continue
        rules = suppressions[lineno]
        if not rules or _matches_rule(finding.rule.id, rules):
            return True
    return False


def _is_excluded(name: str, relative: str, patterns: Sequence[str]) -> bool:
    """Исключение задаётся либо именем каталога/файла, либо glob-ом по пути."""
    return _matches_any(name, patterns) or _matches_any(relative, patterns)


def _candidate_files(
    root: Path,
    exclude: Sequence[str],
    on_error: Callable[[OSError], None] | None = None,
    *,
    production_only: bool = False,
) -> list[Path]:
    if root.is_file():
        return [root]

    # Без onerror os.walk проглатывает ошибки листинга, и каталог без
    # прав давал ноль находок, ноль ошибок и код 0.
    def _report(error: OSError) -> None:
        if on_error is not None:
            on_error(error)

    candidates: list[Path] = []
    try:
        boundary = root.resolve(strict=True)
    except (OSError, RuntimeError):
        _report(OSError(0, "cannot resolve scan root", str(root)))
        return candidates

    def contained(path: Path) -> bool:
        try:
            if path.resolve(strict=True).is_relative_to(boundary):
                return True
        except (OSError, RuntimeError):
            pass
        _report(OSError(0, "path outside scan root or cannot resolve", str(path)))
        return False

    ancestry: dict[Path, tuple[Path, ...]] = {root: (boundary,)}
    for dirpath, dirnames, filenames in os.walk(root, onerror=_report):
        current = Path(dirpath)
        # Обрезаем дерево на месте: в node_modules и .git незачем заходить.
        dirnames[:] = [
            d
            for d in dirnames
            if d not in DEFAULT_EXCLUDED_DIRS
            and not (production_only and d in PRODUCTION_EXCLUDED_DIRS)
            and not _is_excluded(d, (current / d).relative_to(root).as_posix(), exclude)
            and contained(current / d)
        ]
        dirnames.sort()
        children = []
        for name in dirnames:
            path = current / name
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError):
                _report(OSError(0, "cannot resolve directory", str(path)))
                continue
            parents = ancestry[current]
            if resolved in parents:
                _report(OSError(0, "directory cycle", str(path)))
                continue
            ancestry[path] = (*parents, resolved)
            children.append(name)
        dirnames[:] = children
        for filename in sorted(filenames):
            path = current / filename
            if _is_excluded(filename, path.relative_to(root).as_posix(), exclude):
                continue
            if contained(path):
                candidates.append(path)
    return candidates


def discover_files(
    root: Path,
    exclude: Sequence[str] = (),
    on_error: Callable[[OSError], None] | None = None,
    *,
    production_only: bool = False,
) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {
        "compose": [],
        "pg_hba": [],
        "postgresql_conf": [],
        "sshd_config": [],
        "systemd_unit": [],
        "dockerfile": [],
        "dotenv": [],
        "login_defs": [],
        "pwquality": [],
        "useradd_defaults": [],
        "rsyslog": [],
        "nginx": [],
        "postfix_main": [],
    }

    for path in _candidate_files(root, exclude, on_error, production_only=production_only):
        name = path.name
        if _matches_any(name, COMPOSE_FILE_PATTERNS):
            found["compose"].append(path)
        elif _matches_any(name, PG_HBA_PATTERNS):
            found["pg_hba"].append(path)
        elif _matches_any(name, POSTGRESQL_CONF_PATTERNS):
            found["postgresql_conf"].append(path)
        elif _matches_any(name, SSHD_CONFIG_PATTERNS):
            found["sshd_config"].append(path)
        elif _matches_any(name, SYSTEMD_UNIT_PATTERNS):
            found["systemd_unit"].append(path)
        elif _matches_any(name, DOCKERFILE_PATTERNS):
            found["dockerfile"].append(path)
        elif name == ".env" or name.startswith(".env.") or name.endswith(".env"):
            found["dotenv"].append(path)
        elif name == "login.defs":
            found["login_defs"].append(path)
        elif name == "pwquality.conf" or (
            path.parent.name == "pwquality.conf.d" and name.endswith(".conf")
        ):
            found["pwquality"].append(path)
        elif name == "useradd" and path.parent.name == "default":
            found["useradd_defaults"].append(path)
        elif name == "rsyslog.conf":
            found["rsyslog"].append(path)
        elif name == "nginx.conf" or (
            path.parent.name in {"conf.d", "sites-enabled"}
            and path.parent.parent.name == "nginx"
            and (path.parent.name == "sites-enabled" or name.endswith(".conf") or root.is_file())
        ):
            found["nginx"].append(path)
        elif name == "main.cf" and path.parent.name.lower() == "postfix":
            found["postfix_main"].append(path)
    main_dirs = {p.parent for p in found["pwquality"] if p.name == "pwquality.conf"}
    found["pwquality"] = [
        p
        for p in found["pwquality"]
        if p.parent.name != "pwquality.conf.d" or p.parent.parent not in main_dirs
    ]
    found["nginx"].sort(key=lambda p: (p.name != "nginx.conf", str(p)))
    return found


def _describe(exc: Exception) -> str:
    # Exception text can contain input lines and credentials. YAML marks carry
    # useful position information, but their string representation has a snippet.
    name = type(exc).__name__
    if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark is not None:
        mark = exc.problem_mark
        return f"{name} (строка {mark.line + 1}, столбец {mark.column + 1})"
    return name


_COMPOSE_V1_ERROR = (
    "нет ни одного ключа верхнего уровня современного compose "
    "(configs, include, name, networks, secrets, services, version, volumes) — похоже на формат "
    "docker-compose v1, который не поддерживается"
)


def _finding(rule: Rule, path: Path, item: CheckResult) -> Finding:
    """Собирает Finding из 3- или 4-элементного результата проверки."""
    location, detail, line = item[0], item[1], item[2]
    suppress_lines = item[3] if len(item) > 3 else ()
    if isinstance(line, SourceLine):
        path, line = Path(line.file), int(line)
    return Finding(
        rule=rule,
        file=str(path),
        location=location,
        detail=detail,
        line=line,
        suppress_lines=tuple(suppress_lines or ()),
    )


def _run_registry(
    result: ScanResult,
    paths: list[Path],
    rules: list[Rule],
    registry: Mapping[str, CheckFn],
    parse: Callable[[Path], Any],
    boundary: Path | None,
) -> None:
    included: set[Path] = set()
    for path in paths:
        if path.resolve() in included:
            continue
        # Один битый или бинарный файл не должен ронять весь прогон:
        # имя файла с расширением .service ещё не гарантирует, что внутри
        # текстовый юнит systemd.
        try:
            if boundary is not None and not path.resolve(strict=True).is_relative_to(boundary):
                raise ValueError("path outside scan root")
            data: Any
            if parse is parse_compose:
                data = parse_compose(path, scan_root=boundary)
            elif parse is parse_pg_hba:
                data = parse_pg_hba(path, scan_root=boundary)
            elif parse is parse_dockerfile:
                data = parse_dockerfile(path, scan_root=boundary)
            else:
                data = parse(path)
            if isinstance(data, NginxConfig):
                included.update(Path(p) for p in data.comment_offsets)
        except Exception as exc:  # noqa: BLE001 — сообщаем и идём дальше
            description = _describe(exc)
            if (
                parse is parse_compose
                and type(exc) is ValueError
                and exc.args == (_COMPOSE_V1_ERROR,)
            ):
                description = _COMPOSE_V1_ERROR
            result.errors.append(
                ScanError(file=str(path), message=f"не удалось разобрать: {description}")
            )
            continue

        # По одной, а не всем блоком: падение любой проверки уничтожало
        # найденное другими правилами и выглядело как ошибка разбора.
        file_findings: list[Finding] = []
        for rule in rules:
            check_fn = registry.get(rule.id)
            if check_fn is None:
                continue
            try:
                file_findings.extend(_finding(rule, path, item) for item in check_fn(data))
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    ScanError(
                        file=str(path),
                        message=f"сбой проверки {rule.id}: {_describe(exc)}",
                    )
                )

        suppression_cache: dict[str, dict[int, set[str]]] = {}
        for finding in file_findings:
            origin = Path(finding.file)
            try:
                if boundary is not None and not origin.resolve(strict=True).is_relative_to(
                    boundary
                ):
                    result.errors.append(
                        ScanError(file=str(path), message="недопустимое происхождение находки")
                    )
                    continue
                if finding.file not in suppression_cache:
                    offsets = (
                        data.comment_offsets
                        if isinstance(data, EnvFile) and origin == path
                        else data.comment_offsets.get(str(origin.resolve()), {})
                        if isinstance(data, (NginxConfig, PostgreSQLConfig))
                        else None
                    )
                    suppression_cache[finding.file] = inline_suppressions(
                        origin, comment_offsets=offsets, scan_root=boundary
                    )
                suppression_candidate = finding
                if isinstance(data, EnvFile) and origin == path:
                    ends = tuple(
                        entry.end_line
                        for entry in data.entries
                        if entry.line == finding.line
                        and entry.end_line is not None
                        and entry.end_line != entry.line
                    )
                    suppression_candidate = replace(
                        finding, suppress_lines=(*finding.suppress_lines, *ends)
                    )
                if _is_suppressed(suppression_candidate, suppression_cache[finding.file]):
                    result.suppressed += 1
                else:
                    result.findings.append(finding)
            except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
                result.errors.append(
                    ScanError(
                        file=str(origin),
                        message=f"не удалось прочитать подавления: {_describe(exc)}",
                    )
                )
                result.findings.append(finding)


def scan(
    root: Path,
    rules_dir: Path = RULES_DIR,
    exclude: Sequence[str] = (),
    select: Sequence[str] = (),
    ignore: Sequence[str] = (),
    uz: int | None = None,
    *,
    production_only: bool = False,
) -> ScanResult:
    """Сканирует root и возвращает находки (по убыванию severity) и ошибки разбора."""
    rules_by_target: dict[str, list[Rule]] = {}
    for rule in filter_by_uz(filter_rules(load_rules(rules_dir), select, ignore), uz):
        rules_by_target.setdefault(rule.target, []).append(rule)

    result = ScanResult()

    def _walk_error(error: OSError) -> None:
        target = getattr(error, "filename", None) or str(root)
        result.errors.append(
            ScanError(file=str(target), message=f"не удалось обойти каталог: {_describe(error)}")
        )

    files = discover_files(root, exclude, _walk_error, production_only=production_only)
    if rules_by_target.get("compose") and not root.is_file():
        compose_names: dict[Path, set[str]] = {}
        for compose_file in files["compose"]:
            compose_names.setdefault(compose_file.parent, set()).add(compose_file.name.lower())
        for directory, names in compose_names.items():
            bases = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
            overrides = {
                "compose.override.yaml",
                "compose.override.yml",
                "docker-compose.override.yaml",
                "docker-compose.override.yml",
            }
            if names & bases and names & overrides:
                result.errors.append(
                    ScanError(
                        file=str(directory), message="объединение Compose файлов не поддерживается"
                    )
                )
    try:
        boundary = root.resolve(strict=True).parent if root.is_file() else root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        result.errors.append(
            ScanError(file=str(root), message=f"не удалось определить границу: {_describe(exc)}")
        )
        return result

    fragment_groups: dict[Path, list[Path]] = {}
    for file in files["pwquality"]:
        if file.parent.name == "pwquality.conf.d":
            fragment_groups.setdefault(file.parent, []).append(file)
    fragment_inputs: dict[Path, tuple[Path, ...]] = {}
    for group in fragment_groups.values():
        ordered = tuple(sorted(group, key=lambda p: p.name))
        fragment_inputs[ordered[0]] = ordered
        files["pwquality"] = [p for p in files["pwquality"] if p not in ordered[1:]]

    registries: list[tuple[str, Mapping[str, CheckFn], Callable[[Path], Any]]] = [
        ("compose", compose_checks.REGISTRY, parse_compose),
        (
            "postgresql_conf",
            postgres_checks.POSTGRESQL_CONF_REGISTRY,
            lambda p: parse_postgresql_conf(p, scan_root=boundary),
        ),
        ("pg_hba", postgres_checks.PG_HBA_REGISTRY, parse_pg_hba),
        ("sshd_config", sshd_checks.REGISTRY, lambda p: parse_sshd_config(p, scan_root=boundary)),
        ("systemd_unit", systemd_checks.REGISTRY, parse_systemd_unit),
        ("dockerfile", dockerfile_checks.REGISTRY, parse_dockerfile),
        ("dotenv", dotenv_checks.REGISTRY, parse_dotenv),
        ("login_defs", linux_checks.LOGIN_DEFS_REGISTRY, parse_login_defs),
        (
            "pwquality",
            linux_checks.PWQUALITY_REGISTRY,
            lambda p: parse_pwquality(p, scan_root=boundary, fragments=fragment_inputs.get(p)),
        ),
        ("useradd_defaults", linux_checks.USERADD_REGISTRY, parse_useradd_defaults),
        ("postfix_main", postfix_checks.REGISTRY, parse_postfix_main),
        ("nginx", nginx_checks.REGISTRY, lambda p: parse_nginx(p, scan_root=boundary)),
        ("rsyslog", linux_checks.RSYSLOG_REGISTRY, lambda p: parse_rsyslog(p, scan_root=boundary)),
    ]
    for target, registry, parse in registries:
        target_rules = rules_by_target.get(target, [])
        # Ни одного активного правила для этого типа файлов — разбирать
        # их незачем. Иначе --select/--ignore не спасали от битого файла
        # отключённого типа: он всё равно давал ошибку разбора и код 3.
        if not target_rules:
            continue
        _run_registry(result, files[target], target_rules, registry, parse, boundary)

    result.findings.sort(key=lambda f: (-int(f.rule.severity), f.file, f.rule.id, f.location))
    result.errors.sort(key=lambda e: e.file)
    return result
