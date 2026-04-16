Run patrol loop for the security analyst spike.

Execution rules:
- First call `alert.fetch` with payload `{"status":["new","open"],"limit":20}`.
- Keep the run budget-aware: target `<=12` tool calls when `max_turns=18`, and reserve turns for final output.
- Process at most `10` alerts this run.
- Treat only `alerts`, `assets`, and `intel_cache` as preloaded facts in the spike; `cases`, `case_alert_links`, `timeline_events`, and `evidence` must be created or refreshed by your tool calls.
- Use `case.get`, `case.timeline`, and `case.explain-link` to reconstruct evidence and attack flow.
- If no case exists yet for the current attack chain, call `alert.detail` on at least one representative alert before creating a new case.
- When multiple alert details are needed in one run, prefer `alert.detail-batch` over repeated `alert.detail` calls.
- For homogeneous alerts in the same stage/case, use representative sampling instead of one-call-per-alert fan-out.
- If the attack chain warrants a new case and `case.get` cannot find it, create it first with `case.upsert`.
- Use exact `case.upsert` schema keys only: `case_id`, `title`, `status`, `overall_severity`, `current_stage`, `primary_actor_id`.
- Do not send extra `case.upsert` fields such as `description`, `severity`, `created_at`, or `updated_at`.
- Use `case.upsert`, `case.link-alert`, and `case.update-risk` to maintain case state when new evidence appears.
- When creating or refreshing multiple cases in one run, prefer `case.upsert-batch`.
- When linking multiple alerts/entities/actor-relations in one run, prefer `case.link-alert-batch`, `assessment.upsert-batch`, `actor.case-link-batch`, and `actor.case-add-observation-batch`.
- Use `evidence.upsert` to persist derived evidence records.
- Use `timeline.upsert` to persist attack-chain timeline nodes.
- For same-stage events in one case, prefer one aggregated `timeline.upsert` node over per-alert timeline fan-out.
- Use `case.update-risk` to persist case-level assessment snapshots into `case_assessments`, even when the case header already reflects the current stage/severity.
- Use `assessment.upsert` to persist entity-level conclusions (`attacker`, `compromised_host`, `noise`, `unknown`).
- Do not downgrade `current_stage` by default; only pass `force_downgrade=true` when evidence clearly invalidates previous stage.
- For alerts triaged in this run, call `alert.ack` to set status to `triaged` (or `closed` when fully handled) so they leave the `new/open` queue.
- Prefer one batched `alert.ack` call for all triaged alerts in the run.
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
