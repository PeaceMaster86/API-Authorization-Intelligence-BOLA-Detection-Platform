from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Endpoint:
    path: str
    method: str
    object_parameters: tuple[str, ...]


def discover(spec: dict[str, Any]) -> list[Endpoint]:
    endpoints = []
    for path, path_item in spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            parameters = [p for p in operation.get("parameters", []) if p.get("in") == "path"]
            names = tuple(
                p["name"] for p in parameters
                if p.get("name", "").lower() in {"id", "resourceid"}
                or p.get("name", "").lower().endswith(("_id", "id"))
            )
            endpoints.append(Endpoint(path, method.upper(), names))
    return endpoints

