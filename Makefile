.PHONY: test build-dashboard lab scan compose-up compose-down

test:
	.venv-local/bin/pytest -q

build-dashboard:
	cd dashboard/frontend && npm ci && npm run build

lab:
	.venv-local/bin/uvicorn lab.target_api.app.main:app --reload

scan:
	.venv-local/bin/python -m scanner.authz_intel.cli scan --config configs/lab.yaml --output report.json

compose-up:
	docker compose up --build

compose-down:
	docker compose down
