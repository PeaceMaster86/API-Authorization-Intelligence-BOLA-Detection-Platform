from __future__ import annotations

from ..auth_provider import AuthenticatedPrincipal
from ..reporting import Evidence, Finding
from ..request_executor import RequestExecutor


class NestedObjectDetector:
    def run(
        self,
        executor: RequestExecutor,
        principals: dict[str, AuthenticatedPrincipal],
        mismatched_pairs: tuple[tuple[int, int], ...] = (
            (10, 5002),
            (20, 5001),
        ),
    ) -> list[Finding]:
        findings: list[Finding] = []
        for principal_name, identity in principals.items():
            if principal_name == "admin":
                continue
            for project_id, task_id in mismatched_pairs:
                response = executor.execute(
                    "GET",
                    f"/api/v1/projects/{project_id}/tasks/{task_id}",
                    headers=identity.headers,
                )
                if (
                    response.status_code == 200
                    and isinstance(response.body, dict)
                    and str(response.body.get("project_id")) == str(project_id)
                    and str(response.body.get("task_id")) == str(task_id)
                ):
                    findings.append(
                        Finding(
                            title="Broken Object Level Authorization - Nested Object Relationship",
                            severity="high",
                            endpoint="/api/v1/projects/{project_id}/tasks/{task_id}",
                            method="GET",
                            principal=principal_name,
                            object_id=f"{project_id}/{task_id}",
                            status_code=200,
                            evidence="Endpoint returned a mismatched parent-child object pair",
                            confidence=0.95,
                            observed_behavior="A child object was returned under an unrelated parent identifier",
                            reproduction_steps=(
                                f"GET /api/v1/projects/{project_id}/tasks/{task_id}.",
                                "Verify that the authenticated principal is authorized for both objects.",
                            ),
                            evidence_data=Evidence(
                                request={
                                    "method": "GET",
                                    "path": f"/api/v1/projects/{project_id}/tasks/{task_id}",
                                },
                                response={"status_code": response.status_code, "body": response.body},
                                verification_result="response identifiers matched the mismatched request pair",
                            ),
                        )
                    )
        return findings
