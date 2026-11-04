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
python -m scanner.authz_intel.cli scan \
  --spec http://127.0.0.1:8000/openapi.json \
  --base-url http://127.0.0.1:8000 \
  --output report.json
```

Tests use the application in-process and do not require PostgreSQL.

