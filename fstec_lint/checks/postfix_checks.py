"""Проверки основного конфигурационного файла Postfix."""

from __future__ import annotations

from .base import CheckResults, config_line

FILTER_KEYS = ("content_filter", "smtpd_milters")


def check_no_mail_filter(settings: dict) -> CheckResults:
    if any(str(settings.get(key, "")).strip() for key in FILTER_KEYS):
        return []
    return [
        (
            "main.cf: content_filter",
            "не задан ни content_filter, ни smtpd_milters: входящие письма "
            "не передаются на проверку (антивирус, фильтр вложений)",
            config_line(settings, "content_filter") or config_line(settings, "smtpd_milters"),
        )
    ]


REGISTRY = {"M001": check_no_mail_filter}
