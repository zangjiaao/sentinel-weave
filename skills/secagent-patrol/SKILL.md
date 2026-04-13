---
name: secagent-patrol
description: Use when Hermes or another agent must triage security alerts through the secagent MCP server, especially for patrol loops, case reconstruction, attack-chain analysis, IP intelligence checks, notification previews, or report drafting.
---

# SecAgent Patrol

## Overview

Use this skill to run an evidence-based patrol loop with `secagent` MCP. Let `MCP` provide deterministic data and let this skill define tool order, dedupe rules, stopping conditions, and report shape.

## Patrol Workflow

1. Confirm the `secagent` MCP server is available before starting analysis.
2. 优先复用 MCP prompt 提供的参数说明；只有在 prompt 不存在时才回退到本 Skill 里的默认 payload。
3. Start every patrol run with `alert.fetch` and a queue-style payload such as `{"status":["new","open"],"limit":20}`.
4. Keep the patrol bounded. Process at most 10 alerts per run and stop when `no_more_alerts`, `time_budget_exceeded`, or `high_risk_case_found`.
5. For the selected case, call `case.get` first, then `case.timeline` to reconstruct the attack path.
6. Call `asset.search` only when ownership, exposed surface, or asset identity is still unclear.
7. Call `case.explain-link` only for alerts that still need an explicit linkage explanation.
8. Call `intel.lookup` only when current case evidence is still insufficient and threat intelligence can add supporting context.
9. Call `notify.preview` only for high-risk escalation and call `report.draft` only when the case is worth reporting or handing off.
10. If there is genuinely nothing new to report, return exactly `[SILENT]`.

## Tool Usage Rules

- Use `alert.fetch` as the first tool in every patrol run.
- Use `case.get` before writing a severity or current-stage conclusion.
- Use `case.timeline` before describing the attack chain across multiple days, IPs, or targets.
- Use `case.explain-link` with a fixed payload shape:
  - `{"case_id":"<case_id>","target_type":"alert","target_id":"<alert_id>"}`
- 不要对同一个 `alert_id` 重复调用 `case.explain-link`，除非出现新的矛盾证据需要重新解释。
- Use `intel.lookup` with a fixed payload shape:
  - `{"indicator":"<ip_or_indicator>","indicator_type":"ip"}`
- 不要对同一个 `indicator` 重复调用 `intel.lookup`，除非缓存状态或证据上下文已经发生变化。
- Use `notify.preview` with patrol defaults:
  - `{"case_id":"<case_id>","channel":"email","template":"high_severity"}`
- Use `report.draft` with patrol defaults:
  - `{"case_id":"<case_id>","template":"standard","tone":"analytical"}`
- Do not spend extra tool calls probing template names during patrol runs.
- Do not treat threat intelligence as the sole source of truth.
- Do not drop into raw-log summarization when structured tools already provide enough evidence.

## Analysis Rules

- Prefer cautious, evidence-based language such as `high-confidence`, `likely`, or `supported by current evidence`.
- If evidence is insufficient, explicitly say what is still unknown and what should be collected next.
- Treat multi-day, multi-IP activity as one case only when `case.timeline`, `case.explain-link`, asset continuity, or evidence continuity support that link.
- When a source IP changes, keep the uncertainty explicit; do not assume the new IP is the same actor without supporting evidence.
- Generate `notify.preview`, not a real notification send.
- Keep `Memory Summary` limited to durable facts that help future patrols.

## Output Contract

- Render all timestamps in `Asia/Shanghai`.
- Prefer `(Asia/Shanghai)` instead of ambiguous abbreviations such as `CST`.
- Always include these sections in the final patrol report:
  - `Tool Calls`
  - `Assessment`
  - `Remaining Uncertainty`
  - `Memory Summary`
- Keep `Tool Calls` concise and list only the tools actually used in the current run.
- Keep `Remaining Uncertainty` separate from `Assessment`.
- Keep `Memory Summary` to 2-4 durable facts.

## Common Mistakes

- Repeating `case.explain-link` for the same alert because the first answer already looked plausible.
- Repeating `intel.lookup` for the same indicator instead of reusing the existing result.
- Calling `notify.preview` or `report.draft` without the patrol defaults and then wasting turns on parameter correction.
- Writing absolute claims before the case has enough evidence.
- Mixing speculative conclusions into `Assessment` without listing them again in `Remaining Uncertainty`.
