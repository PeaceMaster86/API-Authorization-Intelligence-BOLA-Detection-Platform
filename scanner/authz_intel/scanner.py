from __future__ import annotations

import httpx

from .auth_provider import authenticate
from .config import ScannerConfig
from .reporting import Finding
from .request_executor import RequestExecutor


def scan(
    base_url: str,
    object_ids: tuple[int, ...] = (1001, 2001, 3001),
    config: ScannerConfig | None = None,
) -> list[Finding]:
    """Run the configured read-only lab probe."""
    if config is None:
        raise ValueError("scanner configuration is required")
    if config.base_url != base_url.rstrip("/"):
        raise ValueError("base_url does not match scanner configuration")

    findings: list[Finding] = []
    with httpx.Client(
        base_url=base_url, timeout=config.timeout, follow_redirects=False
    ) as client:
        with RequestExecutor(config, client) as executor:
            principals = {
                principal.name: authenticate(client, config, principal)
                for principal in config.principals
            }
            for principal_name, identity in principals.items():
                if principal_name == "admin":
                    continue
                for object_id in object_ids:
                    response = executor.execute(
                        "GET",
                        f"/api/v1/documents/{object_id}",
                        headers=identity.headers,
                    )
                    body = response.body
                    if (
                        response.status_code == 200
                        and isinstance(body, dict)
                        and body.get("owner") != principal_name
                    ):
                        findings.append(
                            Finding(
                                title="Broken Object Level Authorization",
                                severity="high",
                                endpoint=f"/api/v1/documents/{object_id}",
                                method="GET",
                                principal=principal_name,
                                object_id=str(object_id),
                                status_code=response.status_code,
                                evidence="Response exposed an object owned by another principal",
                                confidence=0.98,
                            )
                        )
    return findings
