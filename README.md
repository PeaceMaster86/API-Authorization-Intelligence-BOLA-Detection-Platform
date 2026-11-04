# API Authorization Intelligence & BOLA Detection Platform

This repository contains a small, runnable vertical slice of an evidence-driven
API authorization tester. It includes a deliberately vulnerable FastAPI lab,
secure mode, OpenAPI endpoint discovery, cross-identity BOLA probes, and
JSON/HTML reports.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn lab.target_api.app.main:app --reload
```

The lab defaults to `TARGET_AUTHZ_MODE=vulnerable`. Set it to `secure` to
exercise the negative regression path:

```bash
TARGET_AUTHZ_MODE=secure uvicorn lab.target_api.app.main:app
```

Run the scanner against a running lab:

```bash
export LAB_ALICE_PASSWORD=alice-password
export LAB_BOB_PASSWORD=bob-password
export LAB_CHARLIE_PASSWORD=charlie-password
export LAB_ADMIN_PASSWORD=admin-password
python -m scanner.authz_intel.cli validate --config configs/lab.yaml
python -m scanner.authz_intel.cli scan \
  --config configs/lab.yaml \
  --output report.json
```

The scanner configuration allowlists the target host and reads credentials
from environment variables. Tokens are used only in memory and are not
written to reports. Tests use the application in-process and do not require
PostgreSQL.
