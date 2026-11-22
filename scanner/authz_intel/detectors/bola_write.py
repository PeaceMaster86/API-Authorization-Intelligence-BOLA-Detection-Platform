from __future__ import annotations

from ..auth_provider import AuthenticatedPrincipal
from ..authorization.policy_engine import AccessDecision, PolicyEngine
from ..inventory.object_registry import ObjectRecord
from ..inventory.principal_registry import Principal
from ..reporting import Finding
from ..request_executor import RequestExecutor
from ..verification.state_verifier import state_changed, write_verified


class WriteBOLADetector:
    def run(
        self,
        executor: RequestExecutor,
        principals: dict[str, AuthenticatedPrincipal],
        principal_records: dict[str, Principal],
        resource: ObjectRecord,
        policy_engine: PolicyEngine,
        attacker: str,
        marker: str,
    ) -> Finding | None:
        owner = principal_records.get(resource.owner)
        attacker_principal = principal_records.get(attacker)
        if (
            owner is None
            or attacker_principal is None
            or owner.username not in principals
            or attacker not in principals
        ):
            return None
        if policy_engine.evaluate_access(attacker_principal, resource, "update") != AccessDecision.DENIED:
            return None

        path = f"/api/v1/documents/{resource.object_id}"
        before = executor.execute("GET", path, headers=principals[owner.username].headers)
        if before.status_code != 200 or not isinstance(before.body, dict):
            return None

        try:
            attempted = executor.execute(
                "PATCH",
                path,
                headers=principals[attacker].headers,
                json={"content": marker},
            )
            if attempted.status_code not in {200, 204}:
                return None
            after = executor.execute("GET", path, headers=principals[owner.username].headers)
            if after.status_code != 200 or not isinstance(after.body, dict):
                return None
            if not state_changed(before.body, after.body) or not write_verified(
                before.body, after.body, marker
            ):
                return None
            return Finding(
                title="Broken Object Level Authorization - Unauthorized Document Modification",
                severity="high",
                endpoint="/api/v1/documents/{document_id}",
                method="PATCH",
                principal=attacker,
                object_id=resource.object_id,
                status_code=attempted.status_code,
                evidence=f"Owner re-read confirmed persisted marker {marker}",
                confidence=0.99,
            )
        finally:
            executor.execute(
                "PATCH",
                path,
                headers=principals[owner.username].headers,
                json={
                    "title": before.body.get("title"),
                    "content": before.body.get("content"),
                },
            )
