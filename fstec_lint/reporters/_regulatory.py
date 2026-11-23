"""Display declared class criteria without filtering or certifying findings."""

from __future__ import annotations

from typing import Any

from ..models import Rule
from ..regulatory import metadata


def reference_context(rule: Rule, declared_gis_class: str | None) -> dict[str, Any]:
    result = metadata(rule)
    result["declared_gis_class"] = declared_gis_class
    for reference in result["references"]:
        criteria = reference.get("class_criteria")
        if declared_gis_class is None or not criteria:
            reference["class_criterion"] = "not_determined"
        elif declared_gis_class in criteria:
            reference["class_criterion"] = "declared_class_matches"
        else:
            reference["class_criterion"] = "declared_class_does_not_match"
    return result
