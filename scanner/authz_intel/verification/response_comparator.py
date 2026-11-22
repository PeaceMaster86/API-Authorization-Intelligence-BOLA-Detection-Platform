from __future__ import annotations

from typing import Any


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize(item)
            for key, item in value.items()
            if key not in {"created_at", "updated_at", "request_id"}
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def compare_object_response(baseline: dict[str, Any], observed: dict[str, Any]) -> dict[str, bool]:
    baseline_normalized = normalize(baseline)
    observed_normalized = normalize(observed)
    return {
        "same_id": str(baseline.get("id")) == str(observed.get("id")),
        "same_owner": baseline.get("owner") == observed.get("owner"),
        "same_tenant": baseline.get("tenant") == observed.get("tenant"),
        "same_marked_content": (
            baseline.get("content") is not None
            and baseline.get("content") == observed.get("content")
        ),
        "matching_normalized_body": baseline_normalized == observed_normalized,
    }
