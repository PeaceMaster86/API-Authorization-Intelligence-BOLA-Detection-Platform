from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from ..inventory.object_registry import ObjectRecord
from ..inventory.ownership_mapper import (
    is_explicitly_shared,
    is_resource_owner,
    is_same_tenant,
)
from ..inventory.principal_registry import Principal


class AccessDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    INCONCLUSIVE = "inconclusive"


class PolicyEngine:
    def __init__(self, policies: dict[str, dict[str, Any]]) -> None:
        self._policies = policies

    @classmethod
    def load(cls, policy_dir: str | Path) -> PolicyEngine:
        policies: dict[str, dict[str, Any]] = {}
        directory = Path(policy_dir)
        for path in sorted(directory.glob("*.yaml")):
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict) or "resource" not in loaded:
                raise ValueError(f"Invalid authorization policy: {path}")
            resource = loaded["resource"]
            if not isinstance(resource, str):
                raise ValueError(f"Policy resource must be a string: {path}")
            policies[resource] = loaded
        return cls(policies)

    def evaluate_access(
        self,
        principal: Principal,
        resource: ObjectRecord,
        action: str,
    ) -> AccessDecision:
        policy = self._policies.get(resource.resource_type)
        if policy is None:
            return AccessDecision.INCONCLUSIVE

        tenant_policy = policy.get("tenant_isolation", {})
        if isinstance(tenant_policy, dict) and tenant_policy.get("enabled") is True:
            if not is_same_tenant(principal, resource):
                return AccessDecision.DENIED

        authorization = policy.get("authorization")
        if not isinstance(authorization, dict) or action not in authorization:
            return AccessDecision.INCONCLUSIVE
        relationships = authorization[action]
        if not isinstance(relationships, list):
            return AccessDecision.INCONCLUSIVE

        owner = is_resource_owner(principal, resource)
        shared = is_explicitly_shared(principal, resource)
        admin = principal.role == "admin"

        for relationship in relationships:
            if relationship in {"owner"} and owner:
                return AccessDecision.ALLOWED
            if relationship in {"explicitly_shared", "shared"} and shared:
                return AccessDecision.ALLOWED
            if relationship == "admin" and admin:
                return AccessDecision.ALLOWED
            if relationship == "member" and principal.tenant_id == resource.tenant_id:
                return AccessDecision.ALLOWED
        return AccessDecision.DENIED

    def get_expected_permission(
        self,
        principal: Principal,
        resource: ObjectRecord,
        action: str,
    ) -> AccessDecision:
        return self.evaluate_access(principal, resource, action)
