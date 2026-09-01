"""Проверки Dockerfile. Функции принимают список инструкций из parse_dockerfile."""

from __future__ import annotations

import re

SECRET_ARG_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)", re.IGNORECASE
)
PIPE_TO_SHELL_RE = re.compile(r"(curl|wget)\b.*\|\s*(sh|bash|python[0-9.]*)\b", re.IGNORECASE)


def _loc(instruction: dict) -> str:
    return f"Dockerfile:{instruction['line']}: {instruction['instruction']}"


def _stages(instructions: list[dict]) -> list[list[dict]]:
    stages: list[list[dict]] = []
    current: list[dict] = []
    for inst in instructions:
        if inst["instruction"] == "FROM":
            if current:
                stages.append(current)
            current = [inst]
        else:
            current.append(inst)
    if current:
        stages.append(current)
    return stages


def check_missing_user(instructions: list[dict]) -> list[tuple[str, str]]:
    stages = _stages(instructions)
    if not stages:
        return []
    last_stage = stages[-1]
    if any(i["instruction"] == "USER" for i in last_stage):
        return []
    return [
        (
            _loc(last_stage[0]),
            "в финальном стейдже сборки нет инструкции USER — образ по "
            "умолчанию запускается от root",
        )
    ]


def check_add_remote_url(instructions: list[dict]) -> list[tuple[str, str]]:
    findings = []
    for inst in instructions:
        if inst["instruction"] != "ADD":
            continue
        first_arg = inst["args"].split()[0] if inst["args"].split() else ""
        if first_arg.startswith(("http://", "https://")):
            findings.append(
                (_loc(inst), f"ADD {inst['args']} — загрузка по URL без проверки контрольной суммы")
            )
    return findings


def check_secret_build_arg(instructions: list[dict]) -> list[tuple[str, str]]:
    findings = []
    for inst in instructions:
        if inst["instruction"] != "ARG":
            continue
        name = inst["args"].split("=")[0].strip()
        if SECRET_ARG_RE.search(name):
            findings.append(
                (
                    _loc(inst),
                    f"ARG {inst['args']} — значение попадает в историю слоёв "
                    "образа (docker history)",
                )
            )
    return findings


def check_latest_base_image(instructions: list[dict]) -> list[tuple[str, str]]:
    findings = []
    for inst in instructions:
        if inst["instruction"] != "FROM":
            continue
        image = inst["args"].split()[0] if inst["args"].split() else ""
        if "@sha256:" in image or image.lower() == "scratch":
            continue
        last_segment = image.split("/")[-1]
        if ":" not in last_segment or last_segment.endswith(":latest"):
            findings.append(
                (_loc(inst), f"FROM {image} — базовый образ не закреплён по версии/digest")
            )
    return findings


def check_pipe_to_shell(instructions: list[dict]) -> list[tuple[str, str]]:
    findings = []
    for inst in instructions:
        if inst["instruction"] != "RUN":
            continue
        if PIPE_TO_SHELL_RE.search(inst["args"]):
            findings.append(
                (
                    _loc(inst),
                    f"RUN {inst['args'][:80]} — вывод curl/wget передаётся "
                    "напрямую в shell без проверки",
                )
            )
    return findings


def check_missing_healthcheck(instructions: list[dict]) -> list[tuple[str, str]]:
    if not instructions:
        return []
    if any(i["instruction"] == "HEALTHCHECK" for i in instructions):
        return []
    return [(_loc(instructions[0]), "в Dockerfile не задан HEALTHCHECK")]


REGISTRY = {
    "D001": check_missing_user,
    "D002": check_add_remote_url,
    "D003": check_secret_build_arg,
    "D004": check_latest_base_image,
    "D005": check_pipe_to_shell,
    "D006": check_missing_healthcheck,
}
