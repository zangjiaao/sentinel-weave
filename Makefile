SHELL := /bin/zsh
UV_CACHE_DIR ?= .uv-cache
UV := UV_CACHE_DIR=$(UV_CACHE_DIR) uv

.PHONY: help sync bootstrap lint test check

help:
	@echo "Available targets:"
	@echo "  make sync       # install dependencies"
	@echo "  make bootstrap  # create spike.db from fixtures"
	@echo "  make lint       # run ruff"
	@echo "  make test       # run pytest"
	@echo "  make check      # run lint + test"

sync:
	$(UV) sync --extra dev

bootstrap:
	$(UV) run python -m security_analyst_agent.bootstrap --db-path ./spike.db

lint:
	$(UV) run ruff check .

test:
	$(UV) run pytest tests -q

check: lint test
