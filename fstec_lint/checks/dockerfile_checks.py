"""Проверки Dockerfile. Функции принимают список инструкций из parse_dockerfile."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .base import CheckResult

SECRET_ARG_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
PIPE_TO_SHELL_RE = re.compile(r"(curl|wget)\b.*\|\s*(sh|bash|python[0-9.]*)\b", re.IGNORECASE)
ROOT_UIDS = {"root", "0"}
MAX_LOCATION_ARGS = 60


@dataclass
class Stage:
    """Одна стадия сборки: FROM и всё, что до следующего FROM.

    Инструкции до первого FROM (ARG там легален) складываются в
    псевдостадию с is_from=False, чтобы не выпадать из проверок.
    """

    index: int
    parent: str
    name: str | None
    from_line: int
    is_from: bool = True
    instructions: list[dict] = field(default_factory=list)

    @property
    def label(self) -> str:
        if not self.is_from:
            return "global"
        return f"stage {self.name or self.index}"


def _from_ref(args: str) -> tuple[str, str | None]:
    """'--platform=$X golang:1.23 AS builder' -> ('golang:1.23', 'builder').

    Флаги вида --platform обязательно отбрасываются: иначе за имя образа
    принимается сам флаг и проверка закрепления версии врёт.
    """
    tokens = [token for token in args.split() if not token.startswith("--")]
    if not tokens:
        return "", None
    image = tokens[0]
    name = None
    if len(tokens) >= 3 and tokens[1].upper() == "AS":
        name = tokens[2].lower()
    return image, name


def _stages(instructions: list[dict]) -> list[Stage]:
    stages: list[Stage] = []
    build_count = 0
    for inst in instructions:
        if inst["instruction"] == "FROM":
            image, name = _from_ref(inst["args"])
            build_count += 1
            stages.append(
                Stage(
                    index=build_count,
                    parent=image.lower(),
                    name=name,
                    from_line=inst["line"],
                    instructions=[inst],
                )
            )
            continue
        if not stages:
            stages.append(
                Stage(
                    index=0,
                    parent="",
                    name=None,
                    from_line=inst["line"],
                    is_from=False,
                )
            )
        stages[-1].instructions.append(inst)
    return stages


def _build_stages(stages: list[Stage]) -> list[Stage]:
    return [stage for stage in stages if stage.is_from]


def _stage_by_name(stages: list[Stage], name: str) -> Stage | None:
    if not name:
        return None
    for stage in stages:
        if stage.is_from and stage.name == name:
            return stage
    return None


def _loc(stage: Stage, suffix: str) -> str:
    """Адрес находки без номера строки: он живёт в отдельном поле Finding.

    Номер строки в location делал отпечаток для baseline нестабильным —
    вставка строки в начало файла обнуляла весь принятый долг.
    """
    return f"{stage.label}: {suffix}"


def _short(args: str) -> str:
    args = " ".join(args.split())
    return args if len(args) <= MAX_LOCATION_ARGS else args[:MAX_LOCATION_ARGS] + "…"


def _is_root_user(value: str) -> bool:
    uid = value.strip().strip("\"'").split(":", 1)[0].strip().lower()
    return uid in ROOT_UIDS


def _effective_user(stage: Stage, stages: list[Stage], seen: set[int] | None = None) -> str | None:
    """Пользователь, от которого стартует стадия, с учётом наследования.

    Если в стадии нет USER, но она собрана FROM другой локальной стадии —
    пользователь наследуется оттуда, и правило не должно ругаться.
    """
    seen = seen or set()
    if stage.index in seen:
        return None
    seen.add(stage.index)

    for inst in reversed(stage.instructions):
        if inst["instruction"] == "USER" and inst["args"].strip():
            return inst["args"].strip()

    parent = _stage_by_name(stages, stage.parent)
    if parent is not None:
        return _effective_user(parent, stages, seen)
    return None


def check_missing_user(instructions: list[dict]) -> list[CheckResult]:
    stages = _stages(instructions)
    build_stages = _build_stages(stages)
    if not build_stages:
        return []
    final = build_stages[-1]
    user = _effective_user(final, stages)

    if user is None:
        return [
            (
                _loc(final, "USER"),
                "в финальном стейдже сборки нет инструкции USER — образ по "
                "умолчанию запускается от root",
                final.from_line,
            )
        ]
    if _is_root_user(user):
        return [
            (
                _loc(final, "USER"),
                f"USER {user} — образ явно запускается от root",
                final.from_line,
            )
        ]
    return []


def check_add_remote_url(instructions: list[dict]) -> list[CheckResult]:
    findings = []
    for stage in _stages(instructions):
        for inst in stage.instructions:
            if inst["instruction"] != "ADD":
                continue
            first_arg = inst["args"].split()[0] if inst["args"].split() else ""
            if first_arg.startswith(("http://", "https://")):
                findings.append(
                    (
                        _loc(stage, f"ADD {_short(inst['args'])}"),
                        f"ADD {inst['args']} — загрузка по URL без проверки контрольной суммы",
                        inst["line"],
                    )
                )
    return findings


def check_secret_build_arg(instructions: list[dict]) -> list[CheckResult]:
    findings = []
    for stage in _stages(instructions):
        for inst in stage.instructions:
            if inst["instruction"] != "ARG":
                continue
            name = inst["args"].split("=")[0].strip()
            if SECRET_ARG_RE.search(name):
                findings.append(
                    (
                        _loc(stage, f"ARG {name}"),
                        f"ARG {inst['args']} — значение попадает в историю слоёв "
                        "образа (docker history)",
                        inst["line"],
                    )
                )
    return findings


def check_latest_base_image(instructions: list[dict]) -> list[CheckResult]:
    findings: list[CheckResult] = []
    build_stages = _build_stages(_stages(instructions))
    for position, stage in enumerate(build_stages):
        image = stage.parent
        # FROM builder — ссылка на предыдущую стадию, а не на внешний образ:
        # закреплять там нечего, это не находка.
        if _stage_by_name(build_stages[:position], image) is not None:
            continue
        if not image or "@sha256:" in image or image == "scratch":
            continue
        last_segment = image.split("/")[-1]
        if ":" not in last_segment or last_segment.endswith(":latest"):
            findings.append(
                (
                    _loc(stage, f"FROM {image}"),
                    f"FROM {image} — базовый образ не закреплён по версии/digest",
                    stage.from_line,
                )
            )
    return findings


def check_pipe_to_shell(instructions: list[dict]) -> list[CheckResult]:
    findings = []
    for stage in _stages(instructions):
        for inst in stage.instructions:
            if inst["instruction"] != "RUN":
                continue
            if PIPE_TO_SHELL_RE.search(inst["args"]):
                findings.append(
                    (
                        _loc(stage, f"RUN {_short(inst['args'])}"),
                        f"RUN {inst['args'][:80]} — вывод curl/wget передаётся "
                        "напрямую в shell без проверки",
                        inst["line"],
                    )
                )
    return findings


def check_missing_healthcheck(instructions: list[dict]) -> list[CheckResult]:
    if not instructions:
        return []
    if any(i["instruction"] == "HEALTHCHECK" for i in instructions):
        return []
    return [("HEALTHCHECK", "в Dockerfile не задан HEALTHCHECK", instructions[0]["line"])]


REGISTRY = {
    "D001": check_missing_user,
    "D002": check_add_remote_url,
    "D003": check_secret_build_arg,
    "D004": check_latest_base_image,
    "D005": check_pipe_to_shell,
    "D006": check_missing_healthcheck,
}
