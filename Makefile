SHELL := /bin/zsh
UV_CACHE_DIR ?= .uv-cache
UV := UV_CACHE_DIR=$(UV_CACHE_DIR) uv
MCP_HOST ?= 127.0.0.1
MCP_PORT ?= 8787
MCP_URL ?= http://$(MCP_HOST):$(MCP_PORT)/mcp
API_HOST ?= 127.0.0.1
API_PORT ?= 18080
SPIKE_DB_PATH ?= $(CURDIR)/spike.db

.PHONY: help sync mcp-server web-api bootstrap lint test check sync-hermes sync-hermes-patrol sync-hermes-mcp-url

help:
	@echo "Available targets:"
	@echo "  make sync       # install dependencies"
	@echo "  make mcp-server # run secagent MCP server (streamable-http)"
	@echo "  make web-api    # run FastAPI backend (OpenAPI at /docs)"
	@echo "  make bootstrap  # create spike.db from fixtures"
	@echo "  make lint       # run ruff"
	@echo "  make test       # run pytest"
	@echo "  make check      # run lint + test"
	@echo ""
	@echo "Legacy targets (deprecated): sync-hermes, sync-hermes-patrol, sync-hermes-mcp-url"

sync:
	$(UV) sync --extra dev

sync-hermes:
	@echo "Deprecated: Hermes runtime sync has been retired. Use OpenAI patrol mode via .env."
	@exit 2

sync-hermes-patrol:
	@echo "Deprecated: Hermes patrol runtime has been retired. Use OpenAI patrol mode via .env."
	@exit 2

mcp-server:
	$(UV) run python -m security_analyst_agent.mcp_server --db-path $(SPIKE_DB_PATH) --transport streamable-http --host $(MCP_HOST) --port $(MCP_PORT) --streamable-http-path /mcp

web-api:
	$(UV) run uvicorn security_analyst_agent.web_api:app --reload --host $(API_HOST) --port $(API_PORT)

sync-hermes-mcp-url:
	@echo "Deprecated: Hermes MCP client sync has been retired."
	@exit 2

bootstrap:
	$(UV) run python -m security_analyst_agent.bootstrap --db-path $(SPIKE_DB_PATH)

lint:
	$(UV) run ruff check .

test:
	$(UV) run pytest tests -q

check: lint test
