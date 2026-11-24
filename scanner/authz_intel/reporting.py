from __future__ import annotations

import hashlib
import html
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


_SECRET_KEYS = {
    "authorization",
    "cookie",
    "password",
    "access_token",
    "refresh_token",
    "api_key",
    "x-api-key",
}


def sanitize(value: Any) -> Any:
    """Redact credentials recursively before evidence is persisted."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]"
            if str(key).lower().replace("-", "_") in _SECRET_KEYS
            else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


@dataclass(frozen=True)
class Evidence:
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    verification_result: str = "not_recorded"

    def sanitized(self) -> dict[str, Any]:
        return sanitize(asdict(self))


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    endpoint: str
    method: str
    principal: str
    object_id: str
    status_code: int
    evidence: str
    confidence: float
    category: str = "API1:2023 - Broken Object Level Authorization"
    expected_access: str = "denied"
    observed_behavior: str = ""
    verification_result: str = "confirmed"
    remediation: str = (
        "Enforce object-level authorization on every request and verify that "
        "the authenticated principal may access the specific resource."
    )
    reproduction_steps: tuple[str, ...] = ()
    evidence_data: Evidence = field(default_factory=Evidence)
    finding_id: str = ""

    def __post_init__(self) -> None:
        if not self.finding_id:
            identity = f"{self.method}:{self.endpoint}:{self.principal}:{self.object_id}"
            object.__setattr__(
                self,
                "finding_id",
                "BOLA-" + hashlib.sha256(identity.encode()).hexdigest()[:12],
            )

    def as_report_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence_data"] = self.evidence_data.sanitized()
        result["reproduction_steps"] = list(self.reproduction_steps)
        return sanitize(result)


def write_json(findings: list[Finding], path: str | Path) -> None:
    report = {
        "summary": {
            "total": len(findings),
            "confirmed": sum(item.verification_result == "confirmed" for item in findings),
            "severity": {
                level: sum(item.severity == level for item in findings)
                for level in ("critical", "high", "medium", "low")
            },
        },
        "findings": [finding.as_report_dict() for finding in findings],
    }
    Path(path).write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_html(findings: list[Finding], path: str | Path) -> None:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(finding.finding_id)}</td>"
        f"<td>{html.escape(finding.severity)}</td>"
        f"<td>{html.escape(finding.method + ' ' + finding.endpoint)}</td>"
        f"<td>{html.escape(finding.principal)}</td>"
        f"<td>{html.escape(finding.verification_result)}</td>"
        f"<td>{html.escape(finding.evidence)}</td>"
        "</tr>"
        for finding in findings
    )
    document = (
        "<!doctype html><meta charset='utf-8'>"
        "<title>API Authorization Security Report</title>"
        "<style>body{font-family:system-ui;margin:2rem;color:#172033}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd3df;"
        "padding:.6rem;text-align:left}th{background:#edf1f7}</style>"
        "<h1>API Authorization Security Report</h1>"
        f"<p>{len(findings)} finding(s) recorded.</p>"
        "<table><thead><tr><th>ID</th><th>Severity</th><th>Request</th>"
        "<th>Principal</th><th>Verification</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )
    Path(path).write_text(document, encoding="utf-8")
