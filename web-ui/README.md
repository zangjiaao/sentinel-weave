# Web UI (MVP Shell)

最小页面壳，覆盖：

- 告警工作台 `/alerts`
- 案件 `/cases`
- 资产 `/assets`
- 通知 `/notifications`
- 报告 `/reports`

`/alerts` 页面当前流程：

1. 上传 CSV（创建任务，默认不直接入库）
2. 查看随机抽样与 Agent 映射建议
3. 用户确认后执行映射入库
4. 仅针对该任务触发分析
5. 查看 run 进展、tool 步骤、token 与耗时成本

兼容入口 `/intake` 会自动跳转到 `/alerts`。

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
