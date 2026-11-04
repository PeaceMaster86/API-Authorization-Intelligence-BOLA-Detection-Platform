from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .config import ConfigurationError, ScannerConfig


@dataclass(frozen=True)
class ResponseCapture:
    request_id: str
    status_code: int
    headers: dict[str, str]
    body: object


class RequestExecutor:
    def __init__(self, config: ScannerConfig, client: httpx.Client | None = None) -> None:
        config.validate_target()
        self._config = config
        self._client = client or httpx.Client(
            base_url=config.base_url,
            timeout=config.timeout,
            follow_redirects=False,
        )
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> RequestExecutor:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def execute(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json: object | None = None,
    ) -> ResponseCapture:
        if not path.startswith("/") or path.startswith("//"):
            raise ConfigurationError("request path must be relative to the configured target")
        response = self._client.request(method.upper(), path, headers=headers, json=json)
        if response.is_redirect:
            location = response.headers.get("location", "")
            parsed = urlparse(location)
            if parsed.hostname and parsed.hostname not in self._config.allowed_hosts:
                raise ConfigurationError("target returned a redirect outside the allowed scope")
        try:
            body: object = response.json()
        except ValueError:
            body = response.text
        return ResponseCapture(
            request_id=response.headers.get("x-request-id", ""),
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
        )
