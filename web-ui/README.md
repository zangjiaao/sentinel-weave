# SentinelWeave Web UI

This is the Next.js frontend for SentinelWeave.

## Local Run

```bash
npm install
NEXT_PUBLIC_API_BASE=http://127.0.0.1:18080 npm run dev
```

Open `http://127.0.0.1:3000`.

## Main Entry

- `/alerts` (primary workflow page)
- `/cases`
- `/assets`
- `/notifications`
- `/reports`

## Alerts Page Workflow

1. Batch upload CSV files into queue.
2. Per file, choose template or generate mapping.
3. Batch ingest selected/ready files.
4. Trigger patrol analysis and monitor progress.

## Build Check

```bash
npm run build
```
