import json

from scanner.authz_intel.reporting import Evidence, Finding, write_html, write_json


def test_json_report_contains_structured_sanitized_evidence(tmp_path):
    finding = Finding(
        title="Unauthorized access",
        severity="high",
        endpoint="/documents/{id}",
        method="GET",
        principal="bob",
        object_id="1001",
        status_code=200,
        evidence="Owner marker matched",
        confidence=0.98,
        evidence_data=Evidence(
            request={
                "headers": {"Authorization": "Bearer secret-token"},
                "json": {"password": "secret-password"},
            },
            response={"content": "PRIVATE_MARKER"},
            verification_result="owner re-read matched",
        ),
    )
    output = tmp_path / "report.json"
    write_json([finding], output)
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["summary"]["confirmed"] == 1
    assert report["findings"][0]["finding_id"].startswith("BOLA-")
    evidence = report["findings"][0]["evidence_data"]
    assert evidence["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert evidence["request"]["json"]["password"] == "[REDACTED]"
    assert "secret-token" not in output.read_text(encoding="utf-8")


def test_html_report_escapes_evidence(tmp_path):
    finding = Finding(
        title="XSS-shaped evidence",
        severity="high",
        endpoint="/documents/{id}",
        method="GET",
        principal="bob",
        object_id="1001",
        status_code=200,
        evidence="<script>alert(1)</script>",
        confidence=0.9,
    )
    output = tmp_path / "report.html"
    write_html([finding], output)
    content = output.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
