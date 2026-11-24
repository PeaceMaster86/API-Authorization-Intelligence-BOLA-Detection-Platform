# Sample report

A confirmed finding contains:

- Stable finding ID
- OWASP API1:2023 category
- Endpoint, method, and object ID
- Testing principal and expected decision
- Observed behavior and verification result
- Sanitized request/response evidence
- Reproduction steps and remediation

Example summary:

```json
{
  "finding_id": "BOLA-abc123def456",
  "title": "Broken Object Level Authorization - Unauthorized Document Access",
  "severity": "high",
  "principal": "bob",
  "object_id": "1001",
  "verification_result": "confirmed"
}
```

Generated reports must not contain passwords, bearer tokens, API keys, or
authorization headers.
