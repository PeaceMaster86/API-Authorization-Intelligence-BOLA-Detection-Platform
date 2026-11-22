from __future__ import annotations

from typing import Any


def read_confidence(comparison: dict[str, bool]) -> tuple[str, float]:
    if comparison.get("same_id") and comparison.get("same_owner"):
        if comparison.get("same_marked_content"):
            return "CONFIRMED", 0.98
        if comparison.get("same_tenant"):
            return "HIGH", 0.82
    if comparison.get("matching_normalized_body"):
        return "HIGH", 0.85
    return "INCONCLUSIVE", 0.20
