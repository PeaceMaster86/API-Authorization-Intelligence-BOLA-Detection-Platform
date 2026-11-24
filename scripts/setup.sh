#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv-local
.venv-local/bin/pip install -r requirements.txt
echo "Python environment ready. Run: make test"
