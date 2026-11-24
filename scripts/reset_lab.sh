#!/usr/bin/env bash
set -euo pipefail

curl --fail --silent --show-error -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN:?Set ADMIN_TOKEN to the lab admin token}" \
  "${LAB_URL:-http://127.0.0.1:8000}/api/v1/reset"
printf '\nLab reset complete.\n'
