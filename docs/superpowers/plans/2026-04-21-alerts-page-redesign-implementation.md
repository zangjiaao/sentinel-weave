# Alerts 页面重设计（MVP）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将现有 Intake 页重构为 Alerts 工作台，支持“上传 → 抽样映射 → 用户确认入库 → 任务级触发分析 → 进展与成本可视化”闭环。

**Architecture:** 后端新增“按 job 过滤待处理 ingest events”的触发路径与 run 查询能力；前端新增 `/alerts` 页面作为单页工作台，顶部 Tab + 操作，底部观测输出。原 `/intake` 保留兼容并跳转到 `/alerts`。流程中所有分析动作都绑定当前 job，避免消费全局队列。

**Tech Stack:** FastAPI + SQLite（Python），Next.js App Router（TypeScript/React），pytest，uv。

---

## File Structure / Ownership

- Modify: `src/security_analyst_agent/patrol_trigger.py`
  - 增加可选 `event_ids` 参数，支持“仅处理指定 ingest events”。
- Modify: `src/security_analyst_agent/services/web_backend.py`
  - 新增 job 维度事件解析、任务级触发、任务级 run/成本/步骤聚合查询。
- Modify: `src/security_analyst_agent/web_api.py`
  - 暴露任务级分析触发与进展查询 API。
- Modify: `tests/test_ingest_trigger.py`
  - 增加“指定 event_ids 仅处理子集”测试。
- Modify: `tests/test_web_backend.py`
  - 增加任务级触发与 run 观测测试。
- Modify: `tests/test_web_api.py`
  - 增加新 API 路由测试。
- Create: `web-ui/app/alerts/page.tsx`
  - 新 Alerts 页面入口。
- Create: `web-ui/components/alerts-workbench.tsx`
  - 客户端工作台组件，串联上传、抽样、确认入库、触发分析与轮询。
- Create: `web-ui/app/api/alerts/uploads/import/route.ts`
  - 上传代理（默认 `apply_after_import=false`）。
- Create: `web-ui/app/api/alerts/uploads/[jobId]/sample/route.ts`
  - 抽样代理。
- Create: `web-ui/app/api/alerts/uploads/[jobId]/apply/route.ts`
  - 入库代理。
- Create: `web-ui/app/api/alerts/uploads/[jobId]/analyze/route.ts`
  - 任务级分析触发代理。
- Create: `web-ui/app/api/alerts/uploads/[jobId]/analysis/route.ts`
  - 任务级分析进展查询代理。
- Modify: `web-ui/app/intake/page.tsx`
  - 改为兼容跳转。
- Modify: `web-ui/app/layout.tsx`
  - 导航文案改为“告警”并指向 `/alerts`。
- Modify: `web-ui/app/page.tsx`
  - 首页默认跳转改为 `/alerts`。
- Modify: `web-ui/README.md`
  - 更新页面说明与使用流程。

---

### Task 1: Backend 任务级触发能力（Job-scoped Trigger）

**Files:**
- Modify: `tests/test_ingest_trigger.py`
- Modify: `src/security_analyst_agent/patrol_trigger.py`

- [ ] **Step 1: 写失败测试，锁定“仅处理指定 event_ids”**

```python
def test_trigger_patrol_processes_only_selected_event_ids(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    ingest_alert_bundle(db_path, [_build_alert("alt_scope_001"), _build_alert("alt_scope_002")], source="siem")

    conn = connect_db(db_path)
    rows = conn.execute(
        "select event_id from alert_ingest_events order by ingested_at asc, rowid asc"
    ).fetchall()
    conn.close()
    selected = rows[0]["event_id"]

    monkeypatch.setattr(runner_module, "DEFAULT_OPENAI_WIRE_API", "responses")
    fake_client = _FakeOpenAIClient(
        rounds=[
            {
                "id": "resp_scope_001",
                "output": [
                    {
                        "type": "function_call",
                        "name": "alert_fetch",
                        "call_id": "call_scope_001",
                        "arguments": '{"status":["new","open"],"limit":20}',
                    }
                ],
            },
            {"id": "resp_scope_002", "output_text": "[SILENT]", "output": [{"type": "message", "role": "assistant"}]},
        ]
    )

    result = trigger_patrol_from_ingest(
        db_path,
        trigger_mode="openai",
        openai_client_factory=lambda: fake_client,
        event_ids=[selected],
    )
    assert result["status"] == "success"

    conn = connect_db(db_path)
    states = conn.execute(
        "select event_id, trigger_state from alert_ingest_events order by ingested_at asc, rowid asc"
    ).fetchall()
    conn.close()
    assert states[0]["trigger_state"] == "processed"
    assert states[1]["trigger_state"] == "pending"
```

- [ ] **Step 2: 跑单测确认失败**

Run: `OPENAI_WIRE_API=responses UV_CACHE_DIR=.uv-cache uv run pytest -q tests/test_ingest_trigger.py::test_trigger_patrol_processes_only_selected_event_ids`  
Expected: FAIL（`trigger_patrol_from_ingest()` 不支持 `event_ids` 或行为不符）。

- [ ] **Step 3: 实现最小代码（支持 event_ids 可选过滤）**

```python
def trigger_patrol_from_ingest(..., event_ids: list[str] | None = None, ...) -> dict[str, object]:
    ...
    pending_ids = _load_pending_event_ids(conn)
    if isinstance(event_ids, list) and event_ids:
        pending_set = set(pending_ids)
        requested = [item for item in event_ids if item in pending_set]
        event_ids = requested
    else:
        event_ids = pending_ids
```

```python
if not event_ids:
    conn.close()
    return {
        "triggered": False,
        "processed_events": 0,
        "status": "noop",
        "run_id": None,
        "job_id": job_id,
    }
```

- [ ] **Step 4: 跑相关测试确认通过**

Run: `OPENAI_WIRE_API=responses UV_CACHE_DIR=.uv-cache uv run pytest -q tests/test_ingest_trigger.py`  
Expected: PASS（全部通过）。

- [ ] **Step 5: 提交**

```bash
git add tests/test_ingest_trigger.py src/security_analyst_agent/patrol_trigger.py
git commit -m "feat: support scoped ingest event selection for patrol trigger"
```

---

### Task 2: Backend/API 任务级分析进展与成本查询

**Files:**
- Modify: `tests/test_web_backend.py`
- Modify: `tests/test_web_api.py`
- Modify: `src/security_analyst_agent/services/web_backend.py`
- Modify: `src/security_analyst_agent/web_api.py`

- [ ] **Step 1: 写失败测试（web_backend）**

```python
def test_web_backend_job_analysis_status_returns_run_costs(tmp_path) -> None:
    db_path = tmp_path / "web-job-analysis.db"
    bootstrap_spike_database(db_path)
    # 准备 import job + raw rows + mapped alerts + processed_run_id + patrol_run_costs
    # 调用 get_job_analysis_status(db_path=db_path, job_id="job_demo")
    # 断言包含 run/status/tool_calls/tokens/duration_ms/steps
```

- [ ] **Step 2: 写失败测试（web_api 路由）**

```python
analysis_resp = client.get(f"/api/intake/uploads/{job_id}/analysis")
assert analysis_resp.status_code == 200
assert "run" in analysis_resp.json()
assert "cost" in analysis_resp.json()
assert "steps" in analysis_resp.json()
```

```python
trigger_resp = client.post(f"/api/intake/uploads/{job_id}/trigger-analysis", json={"dry_run": True})
assert trigger_resp.status_code == 200
assert "status" in trigger_resp.json()
```

- [ ] **Step 3: 实现最小代码（web_backend）**

```python
def _resolve_job_pending_event_ids(conn: Any, *, job_id: str) -> list[str]:
    source = f"import_job:{job_id}"
    rows = conn.execute(
        """
        select distinct e.event_id
        from alert_ingest_events e
        join raw_alert_events r on r.normalized_alert_id = e.alert_id
        where r.source = ?
          and e.trigger_state in ('pending', 'failed')
        order by e.ingested_at asc, e.rowid asc
        """,
        (source,),
    ).fetchall()
    return [str(row["event_id"]) for row in rows]
```

```python
def trigger_patrol(*, db_path: Path, job_id: str, dry_run: bool = False) -> dict[str, Any]:
    conn = connect_db(db_path)
    create_schema(conn)
    try:
        event_ids = _resolve_job_pending_event_ids(conn, job_id=job_id)
    finally:
        conn.close()
    return trigger_patrol_from_ingest(
        db_path=db_path,
        job_id=job_id,
        dry_run=dry_run,
        trigger_mode="openai",
        event_ids=event_ids,
    )
```

```python
def get_job_analysis_status(*, db_path: Path, job_id: str) -> dict[str, Any]:
    # 1) 找到该 job 相关 processed_run_id
    # 2) 读取 patrol_runs + patrol_run_costs + agent_tool_calls
    # 3) 输出 run/cost/steps（步骤来自 tool_name 聚合）
    ...
```

- [ ] **Step 4: 实现最小代码（web_api）**

```python
class TriggerAnalysisRequest(BaseModel):
    dry_run: bool = False

@app.post("/api/intake/uploads/{job_id}/trigger-analysis")
def trigger_intake_upload_analysis(job_id: str, body: TriggerAnalysisRequest) -> dict:
    return web_backend.trigger_patrol(db_path=_db_path(), job_id=job_id, dry_run=body.dry_run)

@app.get("/api/intake/uploads/{job_id}/analysis")
def get_intake_upload_analysis(job_id: str) -> dict:
    return web_backend.get_job_analysis_status(db_path=_db_path(), job_id=job_id)
```

- [ ] **Step 5: 跑相关测试确认通过**

Run: `OPENAI_WIRE_API=responses UV_CACHE_DIR=.uv-cache uv run pytest -q tests/test_web_backend.py tests/test_web_api.py`  
Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add tests/test_web_backend.py tests/test_web_api.py src/security_analyst_agent/services/web_backend.py src/security_analyst_agent/web_api.py
git commit -m "feat: add job-scoped analysis trigger and status endpoints"
```

---

### Task 3: 前端 Alerts 工作台重构

**Files:**
- Create: `web-ui/app/alerts/page.tsx`
- Create: `web-ui/components/alerts-workbench.tsx`
- Create: `web-ui/app/api/alerts/uploads/import/route.ts`
- Create: `web-ui/app/api/alerts/uploads/[jobId]/sample/route.ts`
- Create: `web-ui/app/api/alerts/uploads/[jobId]/apply/route.ts`
- Create: `web-ui/app/api/alerts/uploads/[jobId]/analyze/route.ts`
- Create: `web-ui/app/api/alerts/uploads/[jobId]/analysis/route.ts`
- Modify: `web-ui/app/intake/page.tsx`
- Modify: `web-ui/app/layout.tsx`
- Modify: `web-ui/app/page.tsx`
- Modify: `web-ui/app/globals.css`

- [ ] **Step 1: 新建失败快照（手动验证标准）**

Run: `cd web-ui && NEXT_PUBLIC_API_BASE=http://127.0.0.1:18080 npm run dev`  
Expected: 当前没有 `/alerts` 页面，导航仍是“接入中心”，不满足 spec。

- [ ] **Step 2: 实现页面骨架与导航改造**

```tsx
// web-ui/app/alerts/page.tsx
import AlertsWorkbench from "../../components/alerts-workbench";

export default function AlertsPage() {
  return (
    <section>
      <h1 className="title">告警（Alerts）</h1>
      <AlertsWorkbench />
    </section>
  );
}
```

```tsx
// web-ui/app/page.tsx
import { redirect } from "next/navigation";
export default function HomePage() {
  redirect("/alerts");
}
```

```tsx
// web-ui/app/intake/page.tsx
import { redirect } from "next/navigation";
export default function IntakePage() {
  redirect("/alerts");
}
```

- [ ] **Step 3: 实现工作台交互（上传/抽样/确认入库/任务级分析/轮询）**

```tsx
// 核心状态
const [jobId, setJobId] = useState<string | null>(null);
const [sample, setSample] = useState<any | null>(null);
const [applyResult, setApplyResult] = useState<any | null>(null);
const [analysis, setAnalysis] = useState<any | null>(null);
```

```tsx
// 上传：默认 apply_after_import=false，返回 job 后立即拉 sample
await fetch("/api/alerts/uploads/import", { method: "POST", body: formData });
await fetch(`/api/alerts/uploads/${jobId}/sample`);
```

```tsx
// 确认入库
await fetch(`/api/alerts/uploads/${jobId}/apply`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ include_unmapped: true, limit: 500 }),
});
```

```tsx
// 任务级分析 + 轮询
await fetch(`/api/alerts/uploads/${jobId}/analyze`, {...});
setInterval(() => fetch(`/api/alerts/uploads/${jobId}/analysis`), 3000);
```

- [ ] **Step 4: 实现前端代理路由**

```ts
// pattern: web-ui/app/api/alerts/uploads/[jobId]/analysis/route.ts
export async function GET(_: NextRequest, { params }: { params: { jobId: string } }) {
  const upstream = await fetch(`${apiBase()}/api/intake/uploads/${params.jobId}/analysis`, { cache: "no-store" });
  ...
}
```

- [ ] **Step 5: 样式补充，满足“上输入下输出 + tab”**

```css
.alerts-layout { display: grid; gap: 12px; }
.alerts-top { background: #fff; ... }
.alerts-tabs { display: flex; gap: 8px; }
.alerts-bottom { display: grid; gap: 10px; }
```

- [ ] **Step 6: 前端构建校验**

Run: `cd web-ui && npm run build`  
Expected: build 成功，无 TS 报错。

- [ ] **Step 7: 提交**

```bash
git add web-ui/app/alerts/page.tsx web-ui/components/alerts-workbench.tsx web-ui/app/api/alerts web-ui/app/intake/page.tsx web-ui/app/layout.tsx web-ui/app/page.tsx web-ui/app/globals.css
git commit -m "feat(web): redesign intake into alerts workbench flow"
```

---

### Task 4: 文档与端到端验证

**Files:**
- Modify: `web-ui/README.md`
- Modify: `README.md`

- [ ] **Step 1: 更新文档**

```md
- 新入口：/alerts
- 流程：上传 -> 抽样映射 -> 确认入库 -> 任务级分析 -> 进展与成本观察
```

- [ ] **Step 2: 运行测试（后端）**

Run: `OPENAI_WIRE_API=responses UV_CACHE_DIR=.uv-cache uv run pytest -q tests/test_ingest_trigger.py tests/test_web_backend.py tests/test_web_api.py`  
Expected: PASS。

- [ ] **Step 3: 手动验收（本地）**

Run:

```bash
UV_CACHE_DIR=.uv-cache uv run uvicorn security_analyst_agent.web_api:app --reload --port 18080
cd web-ui
NEXT_PUBLIC_API_BASE=http://127.0.0.1:18080 npm run dev
```

Expected:
- `/alerts` 可访问。
- 上传后出现样本与映射摘要。
- 点击“确认入库”后有 mapped/unmapped 统计。
- 点击“分析当前任务”后出现 run 状态、步骤、token/tool/耗时。

- [ ] **Step 4: 最终提交**

```bash
git add web-ui/README.md README.md
git commit -m "docs: document alerts workbench workflow"
```

---

## Spec Coverage Self-Review

- 目标“上输入下输出 + Tab” → Task 3（页面结构与样式）
- “文件上传 + 抽样映射 + 用户确认入库” → Task 3（上传/sample/apply）
- “仅针对任务触发分析” → Task 1 + Task 2（event_ids 过滤 + trigger API）
- “观察进展（状态/步骤/成本）” → Task 2 + Task 3（analysis API + UI 轮询）
- “失败反馈” → Task 3（客户端状态与错误展示）

无 TBD/TODO 占位；任务命名与接口命名前后一致。
