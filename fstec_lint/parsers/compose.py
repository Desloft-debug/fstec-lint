from __future__ import annotations

from pathlib import Path

import yaml


def parse_compose(path: Path) -> dict:
    """Разбирает docker-compose.yml в обычный dict."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}
