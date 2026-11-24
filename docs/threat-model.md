# Threat model

## Assets

- Object data and ownership relationships
- Authentication credentials and bearer tokens
- Scanner evidence and generated reports
- Target availability and data integrity

## Trust boundaries

1. Tester configuration to scanner.
2. Scanner to explicitly allowlisted target.
3. Target responses to evidence storage.
4. Generated reports to dashboard consumers.

## Threats and controls

| Threat | Control |
| --- | --- |
| Scanning an unintended host | Explicit host allowlist and redirect rejection |
| Credential disclosure | Environment-backed credentials and recursive evidence redaction |
| Destructive test impact | Delete tests disabled by default |
| False positive BOLA | Owner baseline, identity/content comparison, and state verification |
| Cross-tenant exposure | Deterministic tenant-aware policy evaluation |
| Weak deployment secret | JWT secret length validation and explicit environment configuration |
| OpenAPI SSRF | OpenAPI URL must use an explicitly allowlisted host |

This tool is for authorized testing only. It must not be used against systems
without explicit permission.
