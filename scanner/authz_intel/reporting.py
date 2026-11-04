from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


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


def write_json(findings: list[Finding], path: str | Path) -> None:
    Path(path).write_text(json.dumps({"findings": [asdict(f) for f in findings]}, indent=2), encoding="utf-8")


def write_html(findings: list[Finding], path: str | Path) -> None:
    rows = "".join(
        f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.method + ' ' + f.endpoint)}</td>"
        f"<td>{html.escape(f.principal)}</td><td>{html.escape(f.evidence)}</td></tr>"
        for f in findings
    )
    Path(path).write_text(
        "<!doctype html><meta charset='utf-8'><title>BOLA report</title>"
        "<h1>BOLA findings</h1><table><tr><th>Severity</th><th>Request</th><th>Principal</th><th>Evidence</th></tr>"
        + rows + "</table>",
        encoding="utf-8",
    )

