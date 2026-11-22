from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import urllib.request

import yaml


SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete"}
OBJECT_PARAMETER_NAMES = {
    "id",
    "resourceid",
    "resource_id",
    "accountid",
    "account_id",
    "user_id",
    "userid",
    "document_id",
    "documentid",
    "project_id",
    "projectid",
    "task_id",
    "taskid",
    "invoice_id",
    "invoiceid",
    "invoice_uuid",
}


@dataclass(frozen=True)
class Endpoint:
    path: str
    method: str
    object_parameters: tuple[str, ...]
    path_parameters: tuple[str, ...] = ()
    query_parameters: tuple[str, ...] = ()
    request_body_schema: str | None = None
    resource_type: str | None = None
    testing_capability: str = "none"


def load_spec(source: str | Path) -> dict[str, Any]:
    text: str
    value = str(source)
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        with urllib.request.urlopen(value, timeout=10) as response:
            text = response.read().decode("utf-8")
    else:
        text = Path(source).read_text(encoding="utf-8")

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        try:
            loaded = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError("OpenAPI document is neither valid JSON nor YAML") from exc
    if not isinstance(loaded, dict):
        raise ValueError("OpenAPI document must contain a JSON/YAML object")
    if "paths" not in loaded:
        raise ValueError("OpenAPI document does not contain a paths field")
    return loaded


def _parameters(path_item: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for parameter in [*path_item.get("parameters", []), *operation.get("parameters", [])]:
        if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
            merged[(str(parameter.get("in", "")), parameter["name"])] = parameter
    return list(merged.values())


def _schema_name(operation: dict[str, Any]) -> str | None:
    content = operation.get("requestBody", {}).get("content", {})
    if not isinstance(content, dict):
        return None
    for media_type in content.values():
        if not isinstance(media_type, dict):
            continue
        schema = media_type.get("schema")
        if isinstance(schema, dict):
            return str(schema.get("$ref", schema.get("type", "object")))
    return None


def _resource_type(path: str) -> str | None:
    segments = [segment for segment in path.strip("/").split("/") if segment]
    names = [segment for segment in segments if not segment.startswith("{")]
    return names[-1] if names else None


def _is_object_parameter(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    if normalized in OBJECT_PARAMETER_NAMES:
        return True
    return normalized.endswith("_uuid") or normalized.endswith("_id") or normalized == "uuid"


def discover(spec: dict[str, Any]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not isinstance(operation, dict):
                operation = {}
            parameters = _parameters(path_item, operation)
            path_parameters = tuple(
                str(parameter["name"])
                for parameter in parameters
                if parameter.get("in") == "path"
            )
            query_parameters = tuple(
                str(parameter["name"])
                for parameter in parameters
                if parameter.get("in") == "query"
            )
            object_parameters = tuple(
                name for name in path_parameters if _is_object_parameter(name)
            )
            resource_type = _resource_type(path)
            if method.lower() in {"get", "put", "patch", "delete"} and object_parameters:
                capability = "bola_read" if method.lower() == "get" else "bola_write"
                if method.lower() == "delete":
                    capability = "bola_delete_guarded"
            elif method.lower() == "post":
                capability = "resource_creation"
            else:
                capability = "none"
            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    object_parameters=object_parameters,
                    path_parameters=path_parameters,
                    query_parameters=query_parameters,
                    request_body_schema=_schema_name(operation),
                    resource_type=resource_type,
                    testing_capability=capability,
                )
            )
    return endpoints

