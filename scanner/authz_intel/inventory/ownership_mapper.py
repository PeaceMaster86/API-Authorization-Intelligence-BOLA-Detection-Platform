from __future__ import annotations

from .object_registry import ObjectRecord
from .principal_registry import Principal


def is_resource_owner(principal: Principal, resource: ObjectRecord) -> bool:
    return principal.username == resource.owner


def is_explicitly_shared(principal: Principal, resource: ObjectRecord) -> bool:
    return principal.username in resource.shared_with


def is_same_tenant(principal: Principal, resource: ObjectRecord) -> bool:
    return principal.tenant_id == resource.tenant_id
