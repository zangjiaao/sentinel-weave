# Case Convergence (Logical Merge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让离散 `case` 在连续 3 轮高置信关联后自动逻辑合并，并动态重选主案，最终输出可追溯的主攻击链视图。  
**Architecture:** 在现有 MCP 巡检工具流不变的前提下，新增“run 收尾后端收敛器”：评分 -> 候选关系累计 -> 满足阈值触发逻辑合并 -> 主案重选。读写路径增加 canonical 解析，避免继续发散。  
**Tech Stack:** Python 3.11, SQLite, pytest, 现有 `repositories/*` + `tools/*` 分层。

---

### Task 1: 扩展 Schema（case 合并元数据 + 关系表）

**Files:**
- Modify: `src/security_analyst_agent/db.py`
- Test: `tests/test_bootstrap.py`
- Test: `tests/test_case_tools.py`

- [ ] **Step 1: 写失败测试（新增列/表存在）**

```python
def test_schema_contains_case_convergence_columns_and_tables(db_conn) -> None:
    case_cols = {row["name"] for row in db_conn.execute("pragma table_info(cases)").fetchall()}
    assert "canonical_case_id" in case_cols
    assert "merged_into_case_id" in case_cols
    assert "merge_state" in case_cols

    tables = {row["name"] for row in db_conn.execute(
        "select name from sqlite_master where type='table'"
    ).fetchall()}
    assert "case_relations" in tables
    assert "case_merge_events" in tables
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_case_tools.py::test_schema_contains_case_convergence_columns_and_tables -v`  
Expected: `FAIL`（列/表不存在）

- [ ] **Step 3: 最小实现 Schema 变更**

```python
# db.py (create_schema)
create table if not exists case_relations (...);
create table if not exists case_merge_events (...);

# db.py (_ensure_cases_convergence_shape)
if "canonical_case_id" not in columns:
    conn.execute("alter table cases add column canonical_case_id text")
...
conn.execute("""
  update cases
  set canonical_case_id = coalesce(canonical_case_id, case_id),
      merge_state = coalesce(merge_state, 'standalone')
""")
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_case_tools.py::test_schema_contains_case_convergence_columns_and_tables -v`  
Expected: `PASS`

- [ ] **Step 5: 回归基础 DB 测试**

Run: `pytest tests/test_bootstrap.py -v`  
Expected: `PASS`

---

### Task 2: 新增 Case 关系评分服务

**Files:**
- Create: `src/security_analyst_agent/services/case_relation_scoring.py`
- Test: `tests/test_case_relation_scoring.py`

- [ ] **Step 1: 写失败测试（高关联/低关联）**

```python
def test_case_relation_score_is_high_for_same_asset_stage_chain() -> None:
    score = score_case_relation(
        left={"current_stage": "persistence", "asset_ids": {"asset_api_prod"}, "src_ips": {"198.51.100.23"}},
        right={"current_stage": "command_execution", "asset_ids": {"asset_api_prod"}, "src_ips": {"198.51.100.77"}},
    )
    assert score.total >= 0.78

def test_case_relation_score_is_low_for_noise_mismatch() -> None:
    score = score_case_relation(
        left={"current_stage": "recon", "asset_ids": {"asset_static_www"}, "src_ips": {"203.0.113.200"}},
        right={"current_stage": "lateral_prep", "asset_ids": {"asset_api_prod"}, "src_ips": {"198.51.100.77"}},
    )
    assert score.total < 0.68
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_case_relation_scoring.py -v`  
Expected: `FAIL`（模块/函数不存在）

- [ ] **Step 3: 实现评分函数与可解释因子**

```python
@dataclass
class CaseRelationScore:
    total: float
    factors: list[dict]
    supporting_alert_ids: list[str]
    supporting_evidence_ids: list[str]

def score_case_relation(left: dict, right: dict) -> CaseRelationScore:
    # asset overlap + stage continuity + ioc overlap + temporal continuity
    # 返回 total 与 factor 明细
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_case_relation_scoring.py -v`  
Expected: `PASS`

- [ ] **Step 5: 运行相邻服务测试**

Run: `pytest tests/test_case_tools.py::test_case_explain_link_shows_positive_factors -v`  
Expected: `PASS`

---

### Task 3: 新增关系仓储与 streak 状态机

**Files:**
- Create: `src/security_analyst_agent/repositories/case_relations.py`
- Test: `tests/test_case_relations_repo.py`

- [ ] **Step 1: 写失败测试（streak 递增与重置）**

```python
def test_upsert_case_relation_increments_streak_for_consecutive_runs(db_conn) -> None:
    r1 = upsert_case_relation_candidate(db_conn, "run_1", "case_a", "case_b", 0.8, "reason", [], [])
    r2 = upsert_case_relation_candidate(db_conn, "run_2", "case_a", "case_b", 0.82, "reason", [], [])
    assert r1["streak_count"] == 1
    assert r2["streak_count"] == 2

def test_upsert_case_relation_resets_streak_when_score_drops(db_conn) -> None:
    upsert_case_relation_candidate(db_conn, "run_1", "case_a", "case_b", 0.8, "reason", [], [])
    r2 = upsert_case_relation_candidate(db_conn, "run_2", "case_a", "case_b", 0.5, "reason", [], [])
    assert r2["streak_count"] == 0
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_case_relations_repo.py -v`  
Expected: `FAIL`

- [ ] **Step 3: 实现仓储函数**

```python
def normalize_case_pair(case_a: str, case_b: str) -> tuple[str, str]:
    return tuple(sorted((case_a, case_b)))

def upsert_case_relation_candidate(..., score: float, ...):
    # 写入/更新 case_relations
    # 按阈值计算 status 与 streak_count
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_case_relations_repo.py -v`  
Expected: `PASS`

- [ ] **Step 5: 回归 schema 相关测试**

Run: `pytest tests/test_bootstrap.py tests/test_case_tools.py::test_schema_contains_case_convergence_columns_and_tables -v`  
Expected: `PASS`

---

### Task 4: run 收尾自动收敛（两阶段 + N=3）

**Files:**
- Create: `src/security_analyst_agent/services/case_convergence.py`
- Modify: `src/security_analyst_agent/repositories/audit.py`
- Test: `tests/test_audit_logs.py`
- Test: `tests/test_case_convergence_flow.py`

- [ ] **Step 1: 写失败测试（连续 3 轮后 confirmed + 合并）**

```python
def test_mcp_auto_run_triggers_case_convergence_after_ack(db_conn) -> None:
    # 构造两个 case 跨 3 run 高分候选
    # 第三轮后应产生 confirmed relation + merge event
    assert has_confirmed_relation(db_conn, "case_a", "case_b") is True
    assert has_merge_event(db_conn) is True
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_case_convergence_flow.py -v`  
Expected: `FAIL`

- [ ] **Step 3: 实现收敛服务并挂接到 run 结束**

```python
# services/case_convergence.py
def run_case_convergence_for_run(conn, run_id: str) -> dict:
    # 1) 收集本轮触达 case
    # 2) 两两评分并 upsert relation
    # 3) 达到 merge 阈值且 streak>=3 -> apply logical merge
    # 4) 写 case_merge_events

# repositories/audit.py (finalize_mcp_auto_run_after_tool)
if tool_name == "alert.ack" and pending_count == 0:
    _finish_auto_patrol_run(...)
    run_case_convergence_for_run(conn, run_id=run_id)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_case_convergence_flow.py tests/test_audit_logs.py::test_mcp_alert_fetch_starts_auto_patrol_run_and_tags_run_id -v`  
Expected: `PASS`

- [ ] **Step 5: 扩展回归**

Run: `pytest tests/test_audit_logs.py -v`  
Expected: `PASS`

---

### Task 5: 动态主案重选 + case 工具 canonical 重定向

**Files:**
- Modify: `src/security_analyst_agent/repositories/cases.py`
- Modify: `src/security_analyst_agent/tools/case_tools.py`
- Test: `tests/test_case_tools.py`

- [ ] **Step 1: 写失败测试（写 merged 子案会重定向到主案）**

```python
def test_case_link_alert_redirects_to_canonical_case_when_child_is_merged(db_conn) -> None:
    # 准备 child->canonical 关系
    result = case_link_alert(db_conn, {... "case_id": "case_child", ...})
    assert result["warnings"] == ["case_redirected_to_canonical"]
    active = current_active_case_id_for_alert(db_conn, "alt_day1_scan_01")
    assert active == "case_canonical"
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_case_tools.py::test_case_link_alert_redirects_to_canonical_case_when_child_is_merged -v`  
Expected: `FAIL`

- [ ] **Step 3: 实现 canonical 解析与主案重选**

```python
def resolve_canonical_case_id(conn, case_id: str) -> str:
    row = conn.execute("select canonical_case_id from cases where case_id = ?", (case_id,)).fetchone()
    return row["canonical_case_id"] if row and row["canonical_case_id"] else case_id

def reselect_cluster_canonical_case(conn, case_ids: list[str], run_id: str) -> str:
    # 按 timeline/evidence/relationship/recency 计算 score，选主案
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_case_tools.py::test_case_link_alert_redirects_to_canonical_case_when_child_is_merged -v`  
Expected: `PASS`

- [ ] **Step 5: 运行 case 工具全集**

Run: `pytest tests/test_case_tools.py -v`  
Expected: `PASS`

---

### Task 6: 慢速集成场景验收（case 收敛）

**Files:**
- Modify: `src/security_analyst_agent/hermes_slow_verify.py`
- Modify: `docs/runbooks/manifests/hermes-slow-integration.json`
- Test: `tests/test_hermes_slow_verify.py`

- [ ] **Step 1: 写失败测试（主链可收敛）**

```python
def test_verify_final_db_state_checks_case_convergence(tmp_path):
    # 构造 case_relations confirmed + canonical 分配
    summary = _verify_final_db_state(...)
    assert summary["converged_case_clusters_count"] >= 1
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_hermes_slow_verify.py::test_verify_final_db_state_checks_case_convergence -v`  
Expected: `FAIL`

- [ ] **Step 3: 实现 final assertions 扩展**

```python
# hermes_slow_verify.py
if final_assertions.get("min_converged_case_clusters", 0) > actual_clusters:
    raise HermesSlowVerificationError(...)
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_hermes_slow_verify.py -v`  
Expected: `PASS`

- [ ] **Step 5: 运行完整回归子集**

Run: `pytest tests/test_case_tools.py tests/test_audit_logs.py tests/test_hermes_slow_verify.py -v`  
Expected: `PASS`

---

## Self-Review Checklist

- Spec 覆盖：已覆盖 schema、评分、两阶段状态机、动态主案、读写重定向、慢速集成验收。  
- Placeholder 扫描：无 `TODO/TBD`。  
- 一致性：全程使用 `candidate_threshold=0.68`、`merge_threshold=0.78`、`required_streak=3`。  

## 执行交接

Plan complete and saved to `docs/superpowers/plans/2026-04-16-case-convergence-implementation.md`. Two execution options:

1. Subagent-Driven (recommended) - I dispatch a fresh subagent per task, review between tasks, fast iteration
2. Inline Execution - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
