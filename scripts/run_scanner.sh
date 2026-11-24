#!/usr/bin/env bash
set -euo pipefail

exec .venv-local/bin/python -m scanner.authz_intel.cli scan \
  --config "${1:-configs/lab.yaml}" \
  --output "${2:-report.json}"
