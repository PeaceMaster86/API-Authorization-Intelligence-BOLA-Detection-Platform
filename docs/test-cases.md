# Test cases

| ID | Scenario | Expected result |
| --- | --- | --- |
| TC-01 | Owner reads private document | Allowed |
| TC-02 | Same-tenant non-owner reads private document | Denied in secure mode |
| TC-03 | Cross-tenant user reads document | Denied in secure mode |
| TC-04 | Explicitly shared user reads document | Allowed |
| TC-05 | Unauthorized PATCH | Denied in secure mode |
| TC-06 | Unauthorized DELETE | Denied in secure mode |
| TC-07 | Nested parent/child mismatch | Denied in secure mode |
| TC-08 | Missing object evidence in a 200 response | Not confirmed |
| TC-09 | Unauthorized write marker persists | Confirmed only after owner re-read |
| TC-10 | Generated evidence contains a token | Must never occur |

Run the automated suite with `pytest -q`. The lab is deterministic and does
not require PostgreSQL for these tests.
