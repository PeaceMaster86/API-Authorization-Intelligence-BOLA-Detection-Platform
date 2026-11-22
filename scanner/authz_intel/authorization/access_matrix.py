from __future__ import annotations

from typing import Iterable

from ..inventory.object_registry import ObjectRecord
from ..inventory.principal_registry import Principal
from .policy_engine import AccessDecision, PolicyEngine


class AccessMatrix:
    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def evaluate(
        self,
        principals: Iterable[Principal],
        resources: Iterable[ObjectRecord],
        actions: tuple[str, ...] = ("read", "update", "delete"),
    ) -> dict[tuple[str, str, str], AccessDecision]:
        matrix: dict[tuple[str, str, str], AccessDecision] = {}
        for principal in principals:
            for resource in resources:
                for action in actions:
                    matrix[(principal.username, resource.object_id, action)] = (
                        self.engine.evaluate_access(principal, resource, action)
                    )
        return matrix
