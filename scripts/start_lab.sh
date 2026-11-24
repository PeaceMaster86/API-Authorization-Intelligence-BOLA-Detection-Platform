#!/usr/bin/env bash
set -euo pipefail

exec .venv-local/bin/uvicorn lab.target_api.app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
