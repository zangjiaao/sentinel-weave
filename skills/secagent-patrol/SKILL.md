---
name: secagent-patrol
description: Use when Hermes or another agent must triage security alerts through the secagent MCP server, especially for patrol loops, case maintenance, risk escalation, and on-demand reporting.
---

# SecAgent Patrol

## Overview

Use this skill to run an evidence-based patrol loop with `secagent` MCP. Let `MCP` provide deterministic data and let this skill define tool order, dedupe rules, stop conditions, and output shape.

## Patrol Workflow

1. Confirm the `secagent` MCP server is available before starting analysis.
2. 优先复用 MCP prompt 提供的参数说明；只有在 prompt 不存在时才回退到本 Skill 里的默认 payload。
3. Start every patrol run with `alert.fetch` and a queue-style payload such as `{"status":["new","open"],"limit":20}`.
4. Keep the patrol bounded. Process at most 10 alerts per run and stop when `no_more_alerts`, `time_budget_exceeded`, or `high_risk_case_found`.
5. 预算优先：若 run 有 `max_turns`（例如 18），目标控制在 `<=12` 次 tool 调用，并预留至少 3 次回合用于输出最终总结。
6. 对同一攻击链内“同阶段、同类型、同来源”的告警，优先做代表性取样，避免逐条 fan-out 调用。
7. 对同一案件同一阶段，优先写 1 条聚合 `timeline.upsert`，不要为每条同质告警各写一条时间线。
8. `alert.ack` 尽量批量一次提交本轮已处理告警，避免拆成多次调用。
9. 告警详情统一走 `alert.detail-batch`：单条详情也传单元素 `alert_ids`，避免反复单条调用。
10. For each material alert, call `case.get` and `case.timeline`, then `case.explain-link` when explicit linkage evidence is needed.
11. In spike/PoC fixtures, only `alerts` / `assets` / `intel_cache` are preloaded. Treat `cases` / `case_alert_links` / `timeline_events` / `evidence` as derived runtime objects that must be created by the agent.
12. If a case record is missing or stale, create or refresh it with `case.upsert-batch` (single case also uses one-item batch), then maintain it with `case.link-alert-batch` and `case.update-risk`.
13. Use `evidence.upsert` to persist derived evidence records when you identify concrete exploit/webshell/control/lateral facts.
14. Use `timeline.upsert` to persist attack-chain timeline nodes that combine alerts and evidence into a readable step.
15. For attacker/compromised-host conclusions, persist structured entity verdicts with `assessment.upsert-batch` (single entity also uses one-item batch).
16. For alerts already triaged in current run, call `alert.ack` with `status=triaged` (or `closed` when fully handled) to avoid repeated patrol reporting.
17. Call `intel.lookup` only when current case evidence is insufficient and threat intelligence can add supporting context.
18. Call `notify.send` only when escalation threshold is met. This tool is simulation-only and writes delivery records for audit.
19. Call `report.draft` only when the user explicitly requests a report.
20. If there is genuinely nothing new to report, return exactly `[SILENT]`.

## Tool Usage Rules

- Use `alert.fetch` as the first tool in every patrol run.
- 告警详情统一使用 `alert.detail-batch`，单条补证也传单元素数组。
- Use `case.get` before writing a severity or current-stage conclusion.
- Use `case.timeline` before describing the attack chain across multiple days, IPs, or targets.
- Use `case.explain-link` with payload `{"case_id":"<case_id>","target_type":"alert","target_id":"<alert_id>"}`.
- 如果当前还没有案件记录，先对至少一条代表性高信号告警调用 `alert.detail-batch`，再决定是否 `case.upsert-batch` 建案；不要只凭 `alert.fetch` 摘要直接下最终结论。
- 不要对同一个 `alert_id` 重复调用 `case.explain-link`，除非出现新的矛盾证据需要重新解释。
- Use `alert.ack` with payload `{"alert_ids":["<alert_id>"],"status":"triaged"}` after analysis is complete for those alerts.
- Use `case.upsert-batch` when a case needs to be created or refreshed；不要假设 fixture 已经替你建好案件。
- 每个 `case` 可以有一个或多个案内攻击者画像。
- 画像不等于单个 IP；IP 只是 `observation`。
- 不要因为源 IP 变化就创建新的案内画像。
- 当告警已归入案件后，使用 `actor.case-list` 查看该案已有画像。
- 对代表性告警使用 `actor.case-find-candidates` 判断是否属于已有案内画像。
- 如果属于已有画像，使用 `actor.case-add-observation-batch` 追加新的 IP、资产、URI、C2 或 webshell 线索，并用 `actor.case-link-batch` 关联告警/证据/时间线（单条也用 batch）。
- 如果没有合格候选，且该告警代表独立高信号攻击活动，使用 `actor.case-upsert` 创建新的案内画像。
- 噪音告警不创建案内画像。
- 对所有写工具（尤其 `actor.case-upsert` / `actor.case-add-observation-batch` / `actor.case-link-batch` / `case.upsert-batch` / `case.link-alert-batch` / `assessment.upsert-batch`），参数字段一律以对应 MCP prompt 的 schema contract 为准；不要凭记忆猜字段名，也不要使用旧别名字段。
- 在 MCP 巡检中，`alert.detail` / `case.upsert` / `case.link-alert` / `assessment.upsert` / `actor.case-add-observation` / `actor.case-link` 不作为常规入口；即使单条也用对应 `*-batch`。
- Use `case.link-alert-batch` when alerts should be linked to an existing case.
- 需要一次关联多条告警时，优先 `case.link-alert-batch`。
- 需要一次创建/刷新多个案件时，优先 `case.upsert-batch`。
- Use `case.update-risk` when severity/stage/status should change.
- Use `evidence.upsert` to write derived evidence.
- Use `timeline.upsert` to write a timeline node.
- `case.update-risk` 除了更新案件头字段，还用于沉淀“案件级评估”到 `case_assessments`；当本轮出现阶段推进、风险升级，或形成新的案件级判断时必须调用。
- 即使案件头字段已经同步到最新状态，只要本轮新增了 exploit / persistence / command_execution / lateral_prep / reactivation 这类关键证据，仍要调用一次 `case.update-risk` 来写入案件级评估快照。
- 使用 `assessment.upsert-batch` 沉淀实体级结论（例如 `attacker` / `compromised_host` / `noise`）。
- 需要一次写入多条实体结论时，优先 `assessment.upsert-batch`。
- 若主机已出现漏洞利用、webshell 落地、持久化或控制证据，额外写一条 `entity_type="asset"`、`verdict="compromised_host"` 的 `assessment.upsert-batch` item。
- 需要为同一画像追加多条观测或关联多条目标时，优先 `actor.case-add-observation-batch` / `actor.case-link-batch`。
- 默认不要让 `current_stage` 回退；只有证据明确推翻原判断时，才使用 `force_downgrade=true` 显式降级。
- Use `intel.lookup` with payload `{"indicator":"<ip_or_indicator>","indicator_type":"ip"}`.
- 不要对同一个 `indicator` 重复调用 `intel.lookup`，除非缓存状态或证据上下文已经发生变化。
- Use `notify.send` with payload `{"case_id":"<case_id>","channel":"email","template":"high_severity"}`.
- Do not call `report.draft` during regular patrol unless user asks for a report.
- 所有关联、时间线、证据判断必须遵守当前 run 的 `analysis_cutoff_at`，不得引用未来轮次证据。

## Analysis Rules

- Prefer cautious, evidence-based language such as `high-confidence`, `likely`, or `supported by current evidence`.
- If evidence is insufficient, explicitly say what is still unknown and what should be collected next.
- Keep the uncertainty explicit when source infrastructure changes.
- Keep `Memory Summary` limited to durable facts that help future patrols.
- 只有出现漏洞利用、落地、控制、横向等证据时，才把实体写成 `high + attacker`。
- 若仅有扫描或弱信号，优先写 `verdict=noise` 或 `verdict=unknown`，不要直接定高风险攻击者。
- `related_case_id`、`supporting_alert_ids`、`supporting_evidence_ids` 能提供时必须填写，不要只写裸结论。

## Output Contract

- Render all timestamps in `Asia/Shanghai`.
- Prefer `(Asia/Shanghai)` instead of ambiguous abbreviations such as `CST`.
- If no material update exists, output exactly `[SILENT]`.
- If there are updates, include:
  - `Patrol Action Summary`
  - `Escalation`
  - `Remaining Uncertainty`
  - `Memory Summary`

## Common Mistakes

- Repeating `case.explain-link` for the same alert without new evidence.
- Repeating `intel.lookup` for the same indicator instead of reusing cache.
- Forgetting `alert.ack`, causing the same `new/open` alerts to be repeatedly reported.
- Sending escalation before risk threshold is reached.
- Writing reports during patrol runs without explicit user request.
