# Testing methodology

1. Import an OpenAPI JSON or YAML document.
2. Identify resource-oriented operations and object parameters.
3. Load principals, ownership records, and explicit policies.
4. Authenticate each configured identity without persisting tokens.
5. Read the object as its owner to establish a baseline.
6. Evaluate expected authorization before probing with another identity.
7. Compare identifiers, owners, tenants, markers, and normalized content.
8. For enabled write tests, use a harmless marker and verify persistence using
   the owner identity.
9. Restore the original state in a cleanup block.
10. Emit sanitized evidence only when verification supports the finding.

An HTTP 200 response by itself is not a confirmed BOLA. Missing policy data or
insufficient response evidence is treated as inconclusive.
