# API Authorization Intelligence & BOLA Detection Platform

This repository contains a small, runnable vertical slice of an evidence-driven
API authorization tester. It includes a deliberately vulnerable FastAPI lab,
secure mode, OpenAPI endpoint discovery, cross-identity BOLA probes, and
JSON/HTML reports.

See [architecture](docs/architecture.md), [methodology](docs/methodology.md),
[threat model](docs/threat-model.md), [test cases](docs/test-cases.md), and
[limitations](docs/limitations.md) for implementation details.

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
python -m scanner.authz_intel.cli discover --config configs/lab.yaml
python -m scanner.authz_intel.cli endpoints --config configs/lab.yaml
python -m scanner.authz_intel.cli objects
python -m scanner.authz_intel.cli scan \
  --config configs/lab.yaml \
  --output report.json
```

The scanner configuration allowlists the target host and reads credentials
from environment variables. Tokens are used only in memory and are not
written to reports. Tests use the application in-process and do not require
PostgreSQL.

## Docker

Start the lab, PostgreSQL boundary, and dashboard with:

```bash
docker compose up --build
```

The scanner remains a local Python command so its target scope and credentials
stay under tester control. Run `make test` and `make build-dashboard` for the
same checks used in CI.

## Dashboard

The dashboard consumes the generated report and optional inventory API
endpoints. Start it with:

```bash
cd dashboard/frontend
npm install
npm run dev
```

Set `VITE_REPORT_URL` to the URL of a generated JSON report and
`VITE_API_BASE_URL` to the backend inventory API. The UI displays empty or
error states when those data sources are unavailable; it does not fabricate
security statistics.
