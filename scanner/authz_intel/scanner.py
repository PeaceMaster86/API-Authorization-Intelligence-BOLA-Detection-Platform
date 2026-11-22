from __future__ import annotations

import httpx

from .auth_provider import authenticate
from .authorization.policy_engine import PolicyEngine
from .config import ScannerConfig
from .detectors.bola_read import ReadBOLADetector
from .detectors.bola_write import WriteBOLADetector
from .detectors.nested_object import NestedObjectDetector
from .inventory.lab_inventory import lab_objects, lab_principals
from .reporting import Finding
from .request_executor import RequestExecutor


def scan(
    base_url: str,
    object_ids: tuple[int, ...] = (1001, 2001, 3001),
    config: ScannerConfig | None = None,
) -> list[Finding]:
    """Run read, nested, and explicitly enabled write detectors."""
    if config is None:
        raise ValueError("scanner configuration is required")
    if config.base_url != base_url.rstrip("/"):
        raise ValueError("base_url does not match scanner configuration")

    findings: list[Finding] = []
    principals = lab_principals()
    objects = lab_objects()
    principal_records = {principal.username: principal for principal in principals.all()}
    policy_engine = PolicyEngine.load("configs/policies")

    with httpx.Client(
        base_url=base_url, timeout=config.timeout, follow_redirects=False
    ) as client:
        with RequestExecutor(config, client) as executor:
            identities = {
                principal.name: authenticate(client, config, principal)
                for principal in config.principals
            }
            resources = tuple(
                objects.get("documents", str(object_id)) for object_id in object_ids
            )
            findings.extend(
                ReadBOLADetector().run(
                    executor,
                    identities,
                    principal_records,
                    resources,
                    policy_engine,
                )
            )
            findings.extend(
                NestedObjectDetector().run(executor, identities)
            )
            if config.allow_write_tests:
                write_finding = WriteBOLADetector().run(
                    executor,
                    identities,
                    principal_records,
                    objects.get("documents", "1001"),
                    policy_engine,
                    attacker="bob",
                    marker="BOB_UNAUTHORIZED_WRITE_MARKER",
                )
                if write_finding is not None:
                    findings.append(write_finding)
    return findings
