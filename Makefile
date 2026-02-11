PYTHON ?= python3

.PHONY: install-dev lint test scan-example serve docker-up docker-down

install-dev:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -e '.[dev]'

lint:
	.venv/bin/ruff check src tests

test:
	.venv/bin/pytest -q

scan-example:
	.venv/bin/data-leak-scanner scan-http --input examples/sample_http_response.txt --output report.json

serve:
	.venv/bin/data-leak-scanner serve --host 0.0.0.0 --port 8086

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v
