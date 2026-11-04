from __future__ import annotations

from dataclasses import dataclass

import httpx

from .config import ConfigurationError, PrincipalConfig, ScannerConfig, secret_from_env


class AuthenticationError(RuntimeError):
    """Raised when a configured principal cannot authenticate."""


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    name: str
    token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def authenticate(
    client: httpx.Client, config: ScannerConfig, principal: PrincipalConfig
) -> AuthenticatedPrincipal:
    try:
        if principal.auth_type == "bearer_env":
            assert principal.token_env is not None
            return AuthenticatedPrincipal(principal.name, secret_from_env(principal.token_env))
        assert principal.username is not None and principal.password_env is not None
        response = client.post(
            "/api/v1/auth/login",
            json={"username": principal.username, "password": secret_from_env(principal.password_env)},
        )
    except (httpx.HTTPError, ConfigurationError) as exc:
        raise AuthenticationError(f"authentication failed for {principal.name}") from exc
    if response.status_code != 200:
        raise AuthenticationError(
            f"authentication failed for {principal.name}: HTTP {response.status_code}"
        )
    try:
        token = response.json()["access_token"]
    except (ValueError, KeyError, TypeError) as exc:
        raise AuthenticationError(f"authentication response for {principal.name} was invalid") from exc
    if not isinstance(token, str) or not token:
        raise AuthenticationError(f"authentication response for {principal.name} had no token")
    return AuthenticatedPrincipal(principal.name, token)
