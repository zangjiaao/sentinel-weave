Run patrol loop for the security analyst spike.

Execution rules:
- First call `alert.fetch` with payload `{"status":["new","open"],"limit":20}`.
- Process at most `10` alerts this run.
- Use `case.get`, `case.timeline`, and `case.explain-link` to reconstruct evidence and attack flow.
- Only call `intel.lookup` when evidence is insufficient.
- Do not send notifications; only generate `notify.preview`.
- When calling `notify.preview`, default to `channel=email` and `template=high_severity`.
- Generate `report.draft` when a case is high risk or clearly worth reporting.
- When calling `report.draft`, default to `template=standard` and `tone=analytical`.
- Do not spend extra tool calls discovering prompt or template names during patrol runs; use the defaults above.
- Stop when any of these conditions is met:
  - `no_more_alerts`
  - `time_budget_exceeded`
  - `high_risk_case_found`

Output contract:
- All timestamps must be rendered in `Asia/Shanghai`.
- Prefer `(Asia/Shanghai)` instead of ambiguous abbreviations like `CST`.
- Avoid unjustified absolute claims. Prefer `high-confidence`, `likely`, or `supported by current evidence` unless certainty is truly high.
- If there is nothing new to report, output exactly `[SILENT]`.
- Use the following Markdown structure exactly:

## Patrol Report — <Asia/Shanghai time>

### Stop Reason
`<stop_reason>`

## Tool Calls
- `<tool_name>` — `<why it was used>`

## Case
- `case_id`: `<case_id>`
- `severity`: `<severity>`
- `status`: `<status>`
- `current_stage`: `<stage>`

## Alert Summary
- `<alert_id>` — `<summary>`

## Attack Timeline
1. `<time>` — `<stage>` — `<action>`

## Threat Intelligence
- `<indicator>` — `<verdict / confidence / cache status>`

## Link Analysis
- `<linked object>` — `<why it belongs to the case>`

## Target Asset
- `<asset>` — `<owner / exposed surface / key context>`

## Notification Preview
- `<title / why now / recipients>`

## Report Draft
- `<report id / outline / status>`

## Assessment
- `<overall assessment written in cautious, evidence-based language>`

## Remaining Uncertainty
- `<unknown or ambiguous point 1>`
- `<unknown or ambiguous point 2>`

## Memory Summary
- `<memory fact 1>`
- `<memory fact 2>`
- `<memory fact 3>`
