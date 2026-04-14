SHELL := /bin/zsh
UV_CACHE_DIR ?= .uv-cache
UV := UV_CACHE_DIR=$(UV_CACHE_DIR) uv
HERMES_HOME ?= $(HOME)/.hermes
HERMES_CRON_JOB_ID ?= d27a82c0fa79
MCP_HOST ?= 127.0.0.1
MCP_PORT ?= 8787
MCP_URL ?= http://$(MCP_HOST):$(MCP_PORT)/mcp
SPIKE_DB_PATH ?= $(CURDIR)/spike.db

.PHONY: help sync sync-hermes sync-hermes-mcp-url mcp-server bootstrap lint test check

help:
	@echo "Available targets:"
	@echo "  make sync       # install dependencies"
	@echo "  make sync-hermes # sync SOUL/skill/prompt into local Hermes runtime"
	@echo "  make mcp-server # run secagent MCP server (streamable-http)"
	@echo "  make sync-hermes-mcp-url # point Hermes MCP client to MCP_URL"
	@echo "  make bootstrap  # create spike.db from fixtures"
	@echo "  make lint       # run ruff"
	@echo "  make test       # run pytest"
	@echo "  make check      # run lint + test"

sync:
	$(UV) sync --extra dev

sync-hermes:
	mkdir -p $(HERMES_HOME)/skills
	cp hermes/SOUL.template.md $(HERMES_HOME)/SOUL.md
	rm -rf $(HERMES_HOME)/skills/secagent-patrol
	cp -R skills/secagent-patrol $(HERMES_HOME)/skills/secagent-patrol
	hermes cron edit $(HERMES_CRON_JOB_ID) --add-skill secagent-patrol
	hermes cron edit $(HERMES_CRON_JOB_ID) --prompt "$$(cat hermes/patrol-prompt.md)"
	@echo "Synced Hermes runtime config to $(HERMES_HOME) (job: $(HERMES_CRON_JOB_ID))"

mcp-server:
	$(UV) run python -m security_analyst_agent.mcp_server --db-path $(SPIKE_DB_PATH) --transport streamable-http --host $(MCP_HOST) --port $(MCP_PORT) --streamable-http-path /mcp

sync-hermes-mcp-url:
	hermes config set mcp_servers.secagent.url $(MCP_URL)
	hermes mcp test secagent
	@echo "Hermes MCP secagent now points to $(MCP_URL)"

bootstrap:
	$(UV) run python -m security_analyst_agent.bootstrap --db-path ./spike.db

lint:
	$(UV) run ruff check .

test:
	$(UV) run pytest tests -q

check: lint test
