from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ObjectRecord:
    object_id: str
    resource_type: str
    owner: str
    tenant_id: str
    visibility: str
    shared_with: tuple[str, ...] = ()


class ObjectRegistry:
    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], ObjectRecord] = {}

    def register(self, resource: ObjectRecord) -> None:
        self._objects[(resource.resource_type, resource.object_id)] = resource

    def register_many(self, resources: Iterable[ObjectRecord]) -> None:
        for resource in resources:
            self.register(resource)

    def get(self, resource_type: str, object_id: str) -> ObjectRecord:
        resource = self._objects.get((resource_type, object_id))
        if resource is None:
            raise KeyError(f"Unknown object: {resource_type}/{object_id}")
        return resource

    def for_type(self, resource_type: str) -> tuple[ObjectRecord, ...]:
        return tuple(
            sorted(
                (item for item in self._objects.values() if item.resource_type == resource_type),
                key=lambda item: item.object_id,
            )
        )

    def all(self) -> tuple[ObjectRecord, ...]:
        return tuple(
            sorted(
                self._objects.values(),
                key=lambda item: (item.resource_type, item.object_id),
            )
        )
