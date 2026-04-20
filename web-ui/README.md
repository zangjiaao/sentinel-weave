# Web UI (MVP Shell)

最小页面壳，覆盖：

- 接入中心 `/intake`
- 案件 `/cases`
- 资产 `/assets`
- 通知 `/notifications`
- 报告 `/reports`

## 启动

先启动后端 API：

```bash
UV_CACHE_DIR=.uv-cache uv run uvicorn security_analyst_agent.web_api:app --reload --port 18080
```

再启动前端：

```bash
cd web-ui
npm install
NEXT_PUBLIC_API_BASE=http://127.0.0.1:18080 npm run dev
```

