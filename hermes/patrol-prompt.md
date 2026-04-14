Run patrol loop for the security analyst spike.

Execution rules:
- First call `alert.fetch` with payload `{"status":["new","open"],"limit":20}`.
- Process at most `10` alerts this run.
- Use `case.get`, `case.timeline`, and `case.explain-link` to reconstruct evidence and attack flow.
- Use `case.upsert`, `case.link-alert`, and `case.update-risk` to maintain case state when new evidence appears.
- Use `assessment.upsert` to persist entity-level conclusions (`attacker`, `compromised_host`, `noise`, `unknown`).
- Do not downgrade `current_stage` by default; only pass `force_downgrade=true` when evidence clearly invalidates previous stage.
- For alerts triaged in this run, call `alert.ack` to set status to `triaged` (or `closed` when fully handled) so they leave the `new/open` queue.
- Only call `intel.lookup` when evidence is insufficient.
- Never use evidence beyond the current run `analysis_cutoff_at`.
- Do not mark an IP/entity as `high + attacker` on scan-only signals; require exploit/persistence/command/lateral evidence.
- Call `notify.send` only when case risk reaches escalation threshold.
- When calling `notify.send`, default to `channel=email` and `template=high_severity`.
- Only call `report.draft` when user explicitly requests a report.
- Stop when any of these conditions is met:
  - `no_more_alerts`
  - `time_budget_exceeded`
  - `high_risk_case_found`

Output contract:
- If there is no material update, return exactly `[SILENT]`.
- All timestamps must be rendered in `Asia/Shanghai`.
- Prefer `(Asia/Shanghai)` instead of ambiguous abbreviations like `CST`.
- Avoid unjustified absolute claims. Prefer `high-confidence`, `likely`, or `supported by current evidence` unless certainty is truly high.
- Use the following Markdown structure exactly:

## Patrol Action Summary
- `<what changed this run>`

## Escalation
- `<notify.send call summary or 'none'>`

## Remaining Uncertainty
- `<unknown or ambiguous point 1>`
- `<unknown or ambiguous point 2>`

## Memory Summary
- `<memory fact 1>`
- `<memory fact 2>`
- `<memory fact 3>`
