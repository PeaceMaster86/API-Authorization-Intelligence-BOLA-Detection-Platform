from __future__ import annotations

from .object_registry import ObjectRecord, ObjectRegistry
from .principal_registry import Principal, PrincipalRegistry


def lab_principals() -> PrincipalRegistry:
    registry = PrincipalRegistry()
    for principal in (
        Principal("alice", "user", "tenant-a"),
        Principal("bob", "user", "tenant-a"),
        Principal("charlie", "user", "tenant-b"),
        Principal("admin", "admin", "tenant-a"),
    ):
        registry.register(principal)
    return registry


def lab_objects() -> ObjectRegistry:
    registry = ObjectRegistry()
    registry.register_many(
        (
            ObjectRecord("1001", "documents", "alice", "tenant-a", "private"),
            ObjectRecord("1002", "documents", "alice", "tenant-a", "shared", ("bob",)),
            ObjectRecord("2001", "documents", "bob", "tenant-a", "private"),
            ObjectRecord("3001", "documents", "charlie", "tenant-b", "private"),
            ObjectRecord("10", "projects", "alice", "tenant-a", "private"),
            ObjectRecord("20", "projects", "charlie", "tenant-b", "private"),
        )
    )
    return registry
