from __future__ import annotations

from typing import Any

from ..request_executor import ResponseCapture


def state_changed(original: dict[str, Any], observed: dict[str, Any]) -> bool:
    protected_fields = ("title", "content", "description")
    return any(observed.get(field) != original.get(field) for field in protected_fields)


def write_verified(
    original: dict[str, Any],
    after_write: dict[str, Any],
    marker: str,
) -> bool:
    return (
        after_write.get("id") == original.get("id")
        and marker in str(after_write.get("content", ""))
    )
