from __future__ import annotations

import httpx

from .reporting import Finding


IDENTITIES = {"alice": "alice-password", "bob": "bob-password", "charlie": "charlie-password", "admin": "admin-password"}


def scan(base_url: str, object_ids: tuple[int, ...] = (1001, 2001, 3001)) -> list[Finding]:
    findings: list[Finding] = []
    with httpx.Client(base_url=base_url, timeout=10) as client:
        tokens = {}
        for username, password in IDENTITIES.items():
            response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
            response.raise_for_status()
            tokens[username] = response.json()["access_token"]
        for principal in ("bob", "charlie"):
            for object_id in object_ids:
                response = client.get(
                    f"/api/v1/documents/{object_id}",
                    headers={"Authorization": f"Bearer {tokens[principal]}"},
                )
                if response.status_code == 200 and response.json().get("owner") != principal:
                    findings.append(Finding(
                        title="Broken Object Level Authorization",
                        severity="high",
                        endpoint=f"/api/v1/documents/{object_id}",
                        method="GET",
                        principal=principal,
                        object_id=str(object_id),
                        status_code=response.status_code,
                        evidence=f"Returned owner={response.json().get('owner')} content marker",
                        confidence=0.98,
                    ))
    return findings

