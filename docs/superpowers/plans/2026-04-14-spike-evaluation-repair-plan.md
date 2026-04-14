# Spike Evaluation Repair Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复当前 Spike 在多轮巡检中的三个核心问题：未来证据穿越、关联决策与风险判断语义混用、攻击 IP / 资产缺少显式评估记录。

**Architecture:** 保持 `DB facts > Hermes memory` 的边界不变，在数据库中补齐“分析时间边界”和“评估语义分层”。现有 `alert.fetch / case.link-alert / case.update-risk / report.draft` 继续保留；新增的能力优先体现为数据库表、审计导出和最小 Tool 写入路径，而不是大改 Patrol 主流程。

**Tech Stack:** Python, SQLite, Typer CLI, MCP bridge, pytest

---

## 补丁包定义（以本节为准）

- **Patch A（必须）**：修时间边界 + 拆分 `link` / `risk` 语义  
  先修 `src/security_analyst_agent/repositories/alerts.py`、`src/security_analyst_agent/services/link_explainer.py`、`src/security_analyst_agent/repositories/audit.py` 三处根因入口；否则后续结构化沉淀会固化错误结论。
- **Patch B（必须）**：补 `entity_assessments`，显式记录高风险 IP / 失陷主机  
  这轮仅新增一个最小 Tool：`assessment.upsert`，避免“攻击 IP 只存在自然语言报告”。
- **Patch C（建议）**：更新 Hermes Patrol SOP + 验收回放  
  把何时写实体结论、何时只保留假设写进 SOP，并重跑验收回放确认无回归。

## 已确认问题

1. **未来证据泄漏**
   - 第 1 轮的 `case.explain-link` / `alert.detail` 已经引用第 2/3 轮才出现的 `webshell`、`shell connection` 证据。
   - 根因不是模型“乱猜”，而是当前查询默认读取“案件当前全部证据”，没有分析时间边界；当前根因入口在 `src/security_analyst_agent/repositories/alerts.py` 与 `src/security_analyst_agent/services/link_explainer.py`。

2. **语义混用**
   - `alert_decisions` 同时写入 `ack_triaged`、`link_alert` 等操作。
   - 人工审核拿到这张表后，会误把 “告警关联置信度” 当成 “攻击风险置信度”；根因入口在 `src/security_analyst_agent/repositories/audit.py`。

3. **缺少实体级结论**
   - 自然语言报告已经把 `198.51.100.23` 当成主攻击链的一部分。
   - 但数据库里没有一条显式记录说 “这个 IP 是高风险攻击源”，所以导出审计时会被看成遗漏。

4. **导出视图不适合审计**
   - 目前只能看 `alert_decisions`、`case_changes` 这类混合日志。
   - 审核人员真正想回答的是：
     - 谁在攻击？
     - 打了哪些系统？
     - 我为什么这么判断？
     - 这是不是噪音？

## 非目标

- 这轮不做前端改版。
- 这轮不做生产部署、Docker 化、多租户。
- 这轮不追求“完美风险打分算法”；先让结论可解释、可审计、可复盘。

## 目标状态

修复完成后，系统要满足下面 4 条：

1. 任意一轮巡检只能看到 `analysis_cutoff_at` 之前的证据、时间线、关联。
2. “关联判断” 与 “风险判断” 分表记录，导出时不再混淆。
3. 高风险攻击 IP / 资产 / 失陷主机必须有显式 `assessment` 记录。
4. 审核人员不需要反推语义，直接查表就能看到：
   - `198.51.100.23`、`198.51.100.77`、`198.51.100.91` 是高风险攻击源；
   - `203.0.113.10` 是疑似失陷主机；
   - `192.0.2.91`、`192.0.2.123`、`203.0.113.200` 不应被导出成高风险攻击者。

---

### Task 1: 加入分析时间边界并阻断“时间穿越”

**Files:**
- Modify: `src/security_analyst_agent/db.py`
- Modify: `src/security_analyst_agent/patrol_trigger.py`
- Modify: `src/security_analyst_agent/repositories/audit.py`
- Modify: `src/security_analyst_agent/repositories/alerts.py`
- Modify: `src/security_analyst_agent/repositories/cases.py`
- Modify: `src/security_analyst_agent/repositories/context_memory.py`
- Modify: `src/security_analyst_agent/services/link_explainer.py`
- Modify: `src/security_analyst_agent/tools/alert_tools.py`
- Modify: `src/security_analyst_agent/tools/case_tools.py`
- Test: `tests/test_alert_tools.py`
- Test: `tests/test_case_tools.py`
- Test: `tests/test_memory_spike.py`

- [ ] **Step 1: 为 patrol run 增加分析截止时间**

在 `patrol_runs` 增加 `analysis_cutoff_at` 字段，规则为：
- `ingest_event` run：创建 run 时取当前时间；
- `mcp_auto` run：第一次 `alert.fetch` 自动建 run 时取当前时间；
- 后续同一 run 内所有查询都使用这个固定值。

校验命令：

```bash
pytest tests/test_ingest_trigger.py -q
```

- [ ] **Step 2: 在 audit 上下文里绑定 run_id + cutoff**

在 `repositories/audit.py` 增加：
- 读取当前绑定 run 的 `analysis_cutoff_at`
- `load_active_analysis_cutoff(conn) -> str | None`
- 让 Tool 在 dispatch 期间都能拿到统一 cutoff

预期：同一轮里多次查 `alert.detail` / `case.timeline` 不会因为新证据入库而看到不同世界状态。

- [ ] **Step 3: 所有读取案件上下文的查询都支持 cutoff**

至少给下面查询加 `occurred_at <= cutoff` 过滤：
- `load_case_timeline`
- `load_evidence_by_ids`
- `get_case_evidence_summaries`
- `build_case_digest`
- 任何通过 `case_alert_links` 反查案件上下文的逻辑

注意：
- `evidence` 表当前没有时间字段，需要补 `occurred_at`
- `case_alert_links` 读取时要用 `linked_at <= cutoff`

- [ ] **Step 4: 修复当前两个已知穿越入口**

必须先修这两个：
- `alert.detail`
- `case.explain-link`

验收标准：

```bash
pytest tests/test_alert_tools.py tests/test_case_tools.py -q
```

新增断言：
- 第 1 轮告警详情不能包含 `evi_webshell_01`
- 第 1 轮 `case.explain-link` 不能引用第 2/3 轮证据（至少不能包含 `evi_webshell_01` / `evi_shell_conn_01`）

- [ ] **Step 5: 给 memory spike 加回归测试**

在 `tests/test_memory_spike.py` 增加一条场景测试：
- 只应用 `round_01_recon`
- 调 `case.explain-link`
- 断言返回的 `supporting_evidence_ids == []`
  或至少不包含后续轮次证据

---

### Task 2: 拆分“操作日志”“关联决策”“风险评估”

**Files:**
- Modify: `src/security_analyst_agent/db.py`
- Modify: `src/security_analyst_agent/repositories/audit.py`
- Modify: `src/security_analyst_agent/tools/alert_tools.py`
- Modify: `src/security_analyst_agent/tools/case_tools.py`
- Test: `tests/test_audit_logs.py`
- Test: `tests/test_cli_e2e.py`

- [ ] **Step 1: 保留 `alert_decisions`，但重新限定语义**

`alert_decisions` 只记录操作型动作，例如：
- `ack_triaged`
- `ack_closed`
- `ack_missing_alert`

不要再把 `link_alert`、`risk_update` 写进这张表。

- [ ] **Step 2: 新增 `link_decisions` 表**

建议字段：
- `decision_id`
- `occurred_at`
- `run_id`
- `alert_id`
- `case_id`
- `link_confidence`
- `reason_summary`
- `positive_factors_json`
- `negative_factors_json`
- `uncertainties_json`
- `supporting_evidence_ids_json`
- `analysis_cutoff_at`

写入时机：
- `case.link-alert`
- 后续如需保留 `case.explain-link` 的只读解释，可不写表；但真正落地关联时必须写。

- [ ] **Step 3: 新增 `case_assessments` 表**

建议字段：
- `assessment_id`
- `occurred_at`
- `run_id`
- `case_id`
- `risk_level`
- `assessment_confidence`
- `current_stage`
- `verdict`
- `reason_summary`
- `supporting_alert_ids_json`
- `supporting_evidence_ids_json`
- `analysis_cutoff_at`

写入时机：
- `case.update-risk`

- [ ] **Step 4: 更新现有 Tool 的副作用**

更新后应满足：
- `alert.ack` 只写 `alert_decisions`
- `case.link-alert` 写 `link_decisions`
- `case.update-risk` 写 `case_assessments`
- `case_changes` 继续保留，专门记录对象状态前后变化

验收命令：

```bash
pytest tests/test_audit_logs.py tests/test_cli_e2e.py -q
```

- [ ] **Step 5: 回归兼容 CLI 与 MCP**

不删除已有 Tool 名称，不改已有成功响应骨架。
只允许新增审计数据，不允许破坏：
- `case.link-alert`
- `case.update-risk`
- `alert.ack`

---

### Task 3: 增加实体级评估，显式表达“谁是攻击者 / 谁是失陷主机”

**Files:**
- Modify: `src/security_analyst_agent/db.py`
- Create: `src/security_analyst_agent/repositories/assessments.py`
- Create: `src/security_analyst_agent/schemas/assessment_tools.py`
- Create: `src/security_analyst_agent/tools/assessment_tools.py`
- Modify: `src/security_analyst_agent/tool_dispatch.py`
- Modify: `src/security_analyst_agent/cli.py`
- Modify: `src/security_analyst_agent/mcp_server.py`
- Test: `tests/test_cli_e2e.py`
- Test: `tests/test_mcp_server.py`
- Test: `tests/test_audit_logs.py`

- [ ] **Step 1: 新增 `entity_assessments` 表**

建议字段：
- `assessment_id`
- `occurred_at`
- `run_id`
- `entity_type` (`ip` / `asset` / `actor`)
- `entity_key`
- `entity_label`
- `related_case_id`
- `risk_level`
- `assessment_confidence`
- `verdict` (`attacker` / `compromised_host` / `noise` / `unknown`)
- `reason_summary`
- `supporting_alert_ids_json`
- `supporting_evidence_ids_json`
- `first_seen_at`
- `last_seen_at`
- `analysis_cutoff_at`
- `is_current`

- [ ] **Step 2: 提供最小写入 Tool：`assessment.upsert`**

最小 payload 目标：

```json
{
  "entity_type": "ip",
  "entity_key": "198.51.100.23",
  "entity_label": "198.51.100.23",
  "related_case_id": "case_demo_001",
  "risk_level": "high",
  "assessment_confidence": 0.93,
  "verdict": "attacker",
  "reason_summary": "多阶段攻击链中的漏洞利用与 webshell 写入来源",
  "supporting_alert_ids": ["alt_day2_webshell_01"],
  "supporting_evidence_ids": ["evi_webshell_01"]
}
```

这一步是本轮唯一建议新增的核心 Tool；不加它，就无法把 “高风险攻击 IP” 作为结构化结论沉淀下来。

- [ ] **Step 3: 保持一实体一条当前结论，允许历史留痕**

策略：
- 同一 `(entity_type, entity_key, related_case_id)` 只允许一条 `is_current = 1`
- 新评估写入后，把旧记录标成 `is_current = 0`
- 历史记录保留，方便追溯置信度变化

- [ ] **Step 4: 给当前 spike 场景补验收用例**

新增测试断言：
- `198.51.100.23` 有 `high + attacker`
- `198.51.100.77` 有 `high + attacker`
- `198.51.100.91` 有 `high + attacker`
- `203.0.113.10` 有 `high/medium + compromised_host`
- `192.0.2.91` 不存在 `high + attacker`
- `192.0.2.123` 不存在 `high + attacker`

---

### Task 4: 审计 / 导出视图增强（Patch B 可选增强项）

**Files:**
- Modify: `src/security_analyst_agent/cli.py`
- Modify: `src/security_analyst_agent/db.py`
- Test: `tests/test_audit_logs.py`

- [ ] **Step 1: 保留旧命令，但调整命名说明**

保留：
- `audit.alert-decisions`

但说明改成：
- “操作日志（ack/noop/missing）”

- [ ] **Step 2: 新增 3 个审计导出命令**

新增：
- `audit.link-decisions`
- `audit.case-assessments`
- `audit.entity-assessments`

输出目标：
- 字段直接对应新表
- 默认按 `occurred_at desc`
- 支持 `--run-id`
- `audit.entity-assessments` 支持 `--entity-type` / `--risk-level`

- [ ] **Step 3: 给常见审核问题准备直出的字段**

导出字段里直接给出：
- `verdict`
- `risk_level`
- `assessment_confidence`
- `reason_summary`
- `related_case_id`

避免审核方再去拼接 `detail_json`。

- [ ] **Step 4: 写 CLI 回归测试**

验收命令：

```bash
pytest tests/test_audit_logs.py -q
```

至少验证：
- 新命令都能返回 `rows`
- `audit.entity-assessments` 能筛出高风险 IP
- `audit.alert-decisions` 不再出现 `link_alert`

---

### Task 5: 让 Hermes Patrol 学会“什么时候写结论，什么时候只保留假设”

**Files:**
- Modify: `skills/secagent-patrol/SKILL.md`
- Modify: `hermes/patrol-prompt.md`
- Test: `tests/test_hermes_artifacts.py`

- [ ] **Step 1: 补 patrol SOP**

要求 Patrol 规则明确区分三类动作：
- `alert.ack`：队列操作
- `case.link-alert` / `case.update-risk`：案件推进
- `assessment.upsert`：实体结论沉淀

- [ ] **Step 2: 加“证据不足时不得定高风险”规则**

规则建议：
- 只有扫描 / 单点探测，不直接写 `high attacker`
- 有漏洞利用、落地、控制、横向等证据，再写高风险实体结论
- 若只有弱信号，写 `verdict=noise` 或 `verdict=unknown`

- [ ] **Step 3: 加时间边界规则**

Prompt/Skill 明确要求：
- 任何判断必须基于当前 run 的 `analysis_cutoff_at`
- 不得使用未来轮次证据解释当前轮告警

- [ ] **Step 4: 回归文档测试**

验收命令：

```bash
pytest tests/test_hermes_artifacts.py -q
```

- [ ] **Step 5: 执行验收回放（Patch C 收口）**

最小回放要求：
- 复跑当前 spike 的 6 轮场景
- 检查第 1 轮输出不再引用未来证据
- 检查实体评估与审计导出结果与最终验收清单一致

---

## 验收顺序

按这个顺序做，避免“表加了但语义还是错”：

1. **先修时间边界**  
   不先修这个，后面的评估表只会把错误结论更稳定地存下来。

2. **再拆语义**  
   先把 `link` 和 `risk` 分开，才能避免继续误读。

3. **再加实体级评估**  
   否则高风险 IP 仍然只能藏在自然语言里。

4. **最后修导出与 Patrol SOP**  
   这一步让系统结果真正能被人审、被人信；导出增强可与 SOP 一起在 Patch C 收口。

## 最终验收清单

- [ ] 第 1 轮 `case.explain-link` 不再引用 `evi_webshell_01` / `evi_shell_conn_01`
- [ ] `alert.detail` 不再把未来证据拼进当前告警
- [ ] `audit.alert-decisions` 只剩操作型日志
- [ ] `audit.link-decisions` 能看见告警为什么被归到某个案件
- [ ] `audit.case-assessments` 能看见案件何时升到 `high`
- [ ] `audit.entity-assessments` 能直接查到高风险攻击 IP / 疑似失陷主机
- [ ] `198.51.100.23` 在 `entity_assessments` 中存在 `high + attacker` 的显式结论
- [ ] `192.0.2.91`、`192.0.2.123` 不会被结构化导出为 `high + attacker`
- [ ] 复盘当前 spike 时，`198.51.100.23` 不再“只在报告里存在、在结构化数据里缺席”

## 建议实施批次

- **Patch A（必须）**：Task 1 + Task 2
- **Patch B（必须）**：Task 3（实体评估落库）；Task 4 仅保留 `audit.entity-assessments` 所需最小导出
- **Patch C（建议）**：Task 5 + 重新跑 6 轮 spike 验证（验收回放）

如果只做一半，我建议至少先完成 **Patch A**。因为当前最大的问题不是“结论不够多”，而是“时间边界错了，且审计语义会误导人”。
