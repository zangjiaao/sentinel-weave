# SentinelWeave

An AI security analyst that turns noisy alerts into connected cases, attack timelines, and actionable insights.

## What This Repo Includes

- Python backend (`src/security_analyst_agent`)
  - FastAPI service
  - SQLite data model and repositories
  - Alert normalization/mapping pipeline
  - OpenAI patrol trigger and tool orchestration
- Web UI (`web-ui`)
  - Alerts ingestion and mapping workflow
  - Case/asset/notification/report pages (MVP)
- Fixtures and verification scripts for local and slow-run tests

## Quick Start

### 1) Install dependencies

```bash
uv sync --extra dev
cd web-ui && npm install && cd ..
```

### 2) Bootstrap local database

```bash
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.bootstrap --db-path ./spike.db
```

### 3) Configure environment

Create `.env` at repo root (minimum):

```bash
OPENAI_API_KEY=...
OPENAI_BASE_URL=...
OPENAI_PATROL_MODEL=gpt-5.4
OPENAI_WIRE_API=responses
HERMES_PATROL_TRIGGER_MODE=openai
```

### 4) Start backend API

```bash
UV_CACHE_DIR=.uv-cache uv run uvicorn security_analyst_agent.web_api:app --reload --port 18080
```

### 5) Start Web UI

```bash
cd web-ui
NEXT_PUBLIC_API_BASE=http://127.0.0.1:18080 npm run dev
```

Open `http://127.0.0.1:3000/alerts`.

## Current Alerts Workflow (Web)

1. Batch upload CSV files into **Upload Queue**.
2. For each file, either:
   - pick an existing mapping template, or
   - click **Generate Template** to preview and edit mapping.
3. Click **Batch Ingest** to create backend jobs and apply selected mapping.
4. Check progress in **Task Monitor**.
5. Click **Trigger Analysis** to start agent patrol for processed jobs.

## Key API Routes

- `GET /api/intake/uploads`
- `DELETE /api/intake/uploads/{job_id}`
- `POST /api/intake/uploads/preview`
- `POST /api/intake/uploads/import`
- `POST /api/intake/uploads/{job_id}/apply-map`
- `POST /api/intake/uploads/{job_id}/trigger-analysis`
- `GET /api/intake/uploads/{job_id}/analysis`
- `GET /api/cases`
- `GET /api/assets`

## CLI Examples

```bash
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{"status":["new","open"],"limit":5}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli case.get --db-path ./spike.db --payload '{"case_id":"case_demo_001"}'
UV_CACHE_DIR=.uv-cache uv run python -m security_analyst_agent.cli report.draft --db-path ./spike.db --payload '{"case_id":"case_demo_001","template":"incident_report_v1","tone":"professional"}'
```

## Test & Lint

```bash
UV_CACHE_DIR=.uv-cache uv run ruff check .
UV_CACHE_DIR=.uv-cache uv run pytest tests -q
cd web-ui && npm run build
```
