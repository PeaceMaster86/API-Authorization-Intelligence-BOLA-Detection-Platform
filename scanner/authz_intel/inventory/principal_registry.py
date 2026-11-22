from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    tenant_id: str


class PrincipalRegistry:
    def __init__(self) -> None:
        self._principals: dict[str, Principal] = {}

    def register(self, principal: Principal) -> None:
        self._principals[principal.username] = principal

    def get(self, username: str) -> Principal:
        principal = self._principals.get(username)
        if principal is None:
            raise KeyError(f"Unknown principal: {username}")
        return principal

    def all(self) -> tuple[Principal, ...]:
        return tuple(sorted(self._principals.values(), key=lambda item: item.username))
