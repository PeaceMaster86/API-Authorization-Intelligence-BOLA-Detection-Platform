from __future__ import annotations

from typing import Any

from ..auth_provider import AuthenticatedPrincipal
from ..authorization.policy_engine import AccessDecision, PolicyEngine
from ..inventory.object_registry import ObjectRecord
from ..inventory.principal_registry import Principal
from ..reporting import Finding
from ..request_executor import RequestExecutor
from ..verification.confidence_engine import read_confidence
from ..verification.response_comparator import compare_object_response


class ReadBOLADetector:
    def run(
        self,
        executor: RequestExecutor,
        principals: dict[str, AuthenticatedPrincipal],
        principal_records: dict[str, Principal],
        resources: tuple[ObjectRecord, ...],
        policy_engine: PolicyEngine,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for resource in resources:
            owner = principal_records.get(resource.owner)
            if owner is None or owner.username not in principals:
                continue
            baseline = executor.execute(
                "GET",
                f"/api/v1/documents/{resource.object_id}",
                headers=principals[owner.username].headers,
            )
            if baseline.status_code != 200 or not isinstance(baseline.body, dict):
                continue
            for username, identity in principals.items():
                principal = principal_records.get(username)
                if principal is None or username == resource.owner:
                    continue
                expected = policy_engine.evaluate_access(principal, resource, "read")
                if expected != AccessDecision.DENIED:
                    continue
                observed = executor.execute(
                    "GET",
                    f"/api/v1/documents/{resource.object_id}",
                    headers=identity.headers,
                )
                if observed.status_code != 200 or not isinstance(observed.body, dict):
                    continue
                comparison = compare_object_response(baseline.body, observed.body)
                confidence_level, confidence = read_confidence(comparison)
                if confidence_level == "INCONCLUSIVE":
                    continue
                findings.append(
                    Finding(
                        title="Broken Object Level Authorization - Unauthorized Document Access",
                        severity="high",
                        endpoint="/api/v1/documents/{document_id}",
                        method="GET",
                        principal=username,
                        object_id=resource.object_id,
                        status_code=observed.status_code,
                        evidence=(
                            f"Owner baseline and unauthorized response matched "
                            f"id/owner/content markers: {comparison}"
                        ),
                        confidence=confidence,
                    )
                )
        return findings
