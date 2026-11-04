from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

import yaml


class ConfigurationError(ValueError):
    """Raised when scanner configuration is missing or unsafe."""


@dataclass(frozen=True)
class PrincipalConfig:
    name: str
    auth_type: str
    username: str | None = None
    password_env: str | None = None
    token_env: str | None = None


@dataclass(frozen=True)
class ScannerConfig:
    base_url: str
    openapi_url: str | None
    allowed_hosts: frozenset[str]
    timeout: float
    principals: tuple[PrincipalConfig, ...]

    def validate_target(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ConfigurationError("base_url must not contain credentials")
        if parsed.hostname not in self.allowed_hosts:
            raise ConfigurationError(
                f"target host {parsed.hostname!r} is not in allowed_hosts"
            )


def _required_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be a mapping")
    return value


def _principal(name: str, raw: Any) -> PrincipalConfig:
    values = _required_mapping(raw, f"principal {name}")
    auth_type = str(values.get("type", "credentials"))
    if auth_type == "bearer_env":
        token_env = values.get("token_env")
        if not isinstance(token_env, str) or not token_env:
            raise ConfigurationError(f"principal {name} requires token_env")
        return PrincipalConfig(name, auth_type, token_env=token_env)
    if auth_type == "credentials":
        username = str(values.get("username", name))
        password_env = values.get("password_env")
        if not isinstance(password_env, str) or not password_env:
            raise ConfigurationError(f"principal {name} requires password_env")
        return PrincipalConfig(name, auth_type, username=username, password_env=password_env)
    raise ConfigurationError(f"unsupported auth type for {name}: {auth_type}")


def load_config(path: str | Path) -> ScannerConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"cannot read config: {config_path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in {config_path}") from exc

    values = _required_mapping(raw, "configuration")
    target = _required_mapping(values.get("target"), "target")
    base_url = target.get("base_url")
    if not isinstance(base_url, str) or not base_url:
        raise ConfigurationError("target.base_url is required")
    hosts = target.get("allowed_hosts")
    if hosts is None:
        parsed = urlparse(base_url)
        hosts = [parsed.hostname] if parsed.hostname else []
    if not isinstance(hosts, list) or not all(isinstance(host, str) for host in hosts):
        raise ConfigurationError("target.allowed_hosts must be a list of hostnames")

    raw_principals = _required_mapping(values.get("principals"), "principals")
    principals = tuple(_principal(name, item) for name, item in raw_principals.items())
    if not principals:
        raise ConfigurationError("at least one principal is required")

    scanner = _required_mapping(values.get("scanner", {}), "scanner")
    result = ScannerConfig(
        base_url=base_url.rstrip("/"),
        openapi_url=target.get("openapi_url"),
        allowed_hosts=frozenset(hosts),
        timeout=float(scanner.get("timeout", 10.0)),
        principals=principals,
    )
    if result.timeout <= 0 or result.timeout > 120:
        raise ConfigurationError("scanner.timeout must be between 0 and 120 seconds")
    result.validate_target()
    return result


def secret_from_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ConfigurationError(f"required environment variable is not set: {name}")
    return value
