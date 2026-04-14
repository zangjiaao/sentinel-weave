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
5. For each material alert, call `case.get` and `case.timeline`, then `case.explain-link` when explicit linkage evidence is needed.
6. If a case record is missing or stale, update state with `case.upsert`, `case.link-alert`, and `case.update-risk`.
7. For alerts already triaged in current run, call `alert.ack` with `status=triaged` (or `closed` when fully handled) to avoid repeated patrol reporting.
8. Call `intel.lookup` only when current case evidence is insufficient and threat intelligence can add supporting context.
9. Call `notify.send` only when escalation threshold is met. This tool is simulation-only and writes delivery records for audit.
10. Call `report.draft` only when the user explicitly requests a report.
11. If there is genuinely nothing new to report, return exactly `[SILENT]`.

## Tool Usage Rules

- Use `alert.fetch` as the first tool in every patrol run.
- Use `case.get` before writing a severity or current-stage conclusion.
- Use `case.timeline` before describing the attack chain across multiple days, IPs, or targets.
- Use `case.explain-link` with payload `{"case_id":"<case_id>","target_type":"alert","target_id":"<alert_id>"}`.
- 不要对同一个 `alert_id` 重复调用 `case.explain-link`，除非出现新的矛盾证据需要重新解释。
- Use `alert.ack` with payload `{"alert_ids":["<alert_id>"],"status":"triaged"}` after analysis is complete for those alerts.
- Use `case.upsert` when a case needs to be created or refreshed.
- Use `case.link-alert` when an alert should be linked to an existing case.
- Use `case.update-risk` when severity/stage/status should change.
- 默认不要让 `current_stage` 回退；只有证据明确推翻原判断时，才使用 `force_downgrade=true` 显式降级。
- Use `intel.lookup` with payload `{"indicator":"<ip_or_indicator>","indicator_type":"ip"}`.
- 不要对同一个 `indicator` 重复调用 `intel.lookup`，除非缓存状态或证据上下文已经发生变化。
- Use `notify.send` with payload `{"case_id":"<case_id>","channel":"email","template":"high_severity"}`.
- Do not call `report.draft` during regular patrol unless user asks for a report.

## Analysis Rules

- Prefer cautious, evidence-based language such as `high-confidence`, `likely`, or `supported by current evidence`.
- If evidence is insufficient, explicitly say what is still unknown and what should be collected next.
- Keep the uncertainty explicit when source infrastructure changes.
- Keep `Memory Summary` limited to durable facts that help future patrols.

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
