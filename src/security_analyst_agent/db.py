from datetime import datetime, timezone
from pathlib import Path
import sqlite3


def connect_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_case_alert_links_shape(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("pragma table_info(case_alert_links)").fetchall()}
    if not columns:
        return

    if "is_active" not in columns:
        conn.execute("alter table case_alert_links add column is_active integer not null default 1")
    if "unlinked_at" not in columns:
        conn.execute("alter table case_alert_links add column unlinked_at text")

    conn.execute("update case_alert_links set is_active = 1 where is_active is null")
    conn.execute(
        """
        with ranked as (
          select
            rowid,
            row_number() over (partition by alert_id order by linked_at desc, rowid desc) as rank_id
          from case_alert_links
          where is_active = 1
        )
        update case_alert_links
        set is_active = 0, unlinked_at = coalesce(unlinked_at, linked_at)
        where rowid in (select rowid from ranked where rank_id > 1)
        """
    )
    conn.execute(
        """
        create unique index if not exists idx_case_alert_links_active_alert
        on case_alert_links(alert_id)
        where is_active = 1
        """
    )
    conn.execute("create index if not exists idx_case_alert_links_alert_id on case_alert_links(alert_id)")


def _ensure_alerts_shape(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("pragma table_info(alerts)").fetchall()}
    if not columns:
        return
    if "raw_attack_stage" not in columns:
        conn.execute("alter table alerts add column raw_attack_stage text")


def _ensure_patrol_runs_shape(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("pragma table_info(patrol_runs)").fetchall()}
    if not columns:
        return
    if "analysis_cutoff_at" not in columns:
        conn.execute("alter table patrol_runs add column analysis_cutoff_at text")
    conn.execute(
        """
        update patrol_runs
        set analysis_cutoff_at = coalesce(analysis_cutoff_at, started_at)
        where analysis_cutoff_at is null
        """
    )


def _ensure_cases_convergence_shape(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("pragma table_info(cases)").fetchall()}
    if not columns:
        return

    if "canonical_case_id" not in columns:
        conn.execute("alter table cases add column canonical_case_id text")
    if "merged_into_case_id" not in columns:
        conn.execute("alter table cases add column merged_into_case_id text")
    if "merge_state" not in columns:
        conn.execute("alter table cases add column merge_state text")
    if "merge_updated_at" not in columns:
        conn.execute("alter table cases add column merge_updated_at text")

    conn.execute(
        """
        update cases
        set canonical_case_id = coalesce(canonical_case_id, case_id),
            merge_state = coalesce(merge_state, 'standalone'),
            merge_updated_at = coalesce(merge_updated_at, ?)
        """,
        (_now_iso(),),
    )


def _ensure_evidence_shape(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("pragma table_info(evidence)").fetchall()}
    if not columns:
        return
    if "occurred_at" not in columns:
        conn.execute("alter table evidence add column occurred_at text")

    conn.execute(
        """
        update evidence
        set occurred_at = (
          select min(timeline_events.occurred_at)
          from timeline_events
          join json_each(timeline_events.related_evidence_ids)
          where json_each.value = evidence.evidence_id
        )
        where occurred_at is null
        """
    )
    conn.execute(
        """
        update evidence
        set occurred_at = (
          select min(alerts.occurred_at)
          from alerts
          join case_alert_links on case_alert_links.alert_id = alerts.alert_id
          where case_alert_links.case_id = evidence.case_id
        )
        where occurred_at is null
        """
    )
    conn.execute(
        """
        update evidence
        set occurred_at = ?
        where occurred_at is null
        """,
        (_now_iso(),),
    )


def _ensure_verify_spike_round_runs_shape(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        create table if not exists verify_spike_round_runs (
          round_id text primary key,
          applied_at text not null
        )
        """
    )
    legacy_exists = (
        conn.execute(
            """
            select 1
            from sqlite_master
            where type = 'table' and name = 'spike_round_runs'
            """
        ).fetchone()
        is not None
    )
    if not legacy_exists:
        return
    conn.execute(
        """
        insert or ignore into verify_spike_round_runs (round_id, applied_at)
        select round_id, applied_at
        from spike_round_runs
        """
    )
    conn.execute(
        """
        update verify_spike_round_runs
        set applied_at = (
          select spike_round_runs.applied_at
          from spike_round_runs
          where spike_round_runs.round_id = verify_spike_round_runs.round_id
        )
        where exists (
          select 1
          from spike_round_runs
          where spike_round_runs.round_id = verify_spike_round_runs.round_id
            and spike_round_runs.applied_at <> verify_spike_round_runs.applied_at
        )
        """
    )


def _backfill_case_links_from_legacy_alert_case_id(conn: sqlite3.Connection) -> None:
    alert_columns = {row["name"] for row in conn.execute("pragma table_info(alerts)").fetchall()}
    if "case_id" not in alert_columns:
        return

    conn.execute(
        """
        insert into case_alert_links (
          case_id,
          alert_id,
          linked_at,
          confidence,
          reason,
          is_active,
          unlinked_at
        )
        select
          alerts.case_id,
          alerts.alert_id,
          alerts.occurred_at,
          1.0,
          'legacy_alert_case_id_backfill',
          1,
          null
        from alerts
        left join case_alert_links
          on case_alert_links.alert_id = alerts.alert_id
         and case_alert_links.is_active = 1
        where alerts.case_id is not null
          and case_alert_links.alert_id is null
        on conflict(case_id, alert_id) do update set
          linked_at = excluded.linked_at,
          confidence = excluded.confidence,
          reason = excluded.reason,
          is_active = 1,
          unlinked_at = null
        """
    )


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        create table if not exists assets (
          asset_id text primary key,
          asset_name text not null,
          system_name text not null,
          owner_team text,
          internet_exposed integer not null,
          public_ip text,
          domain text
        );
        create table if not exists alerts (
          alert_id text primary key,
          occurred_at text not null,
          title text not null,
          status text not null,
          severity text not null,
          attack_stage text not null,
          raw_attack_stage text,
          src_ip text,
          dst_ip text,
          asset_id text
        );
        create table if not exists cases (
          case_id text primary key,
          title text not null,
          status text not null,
          overall_severity text not null,
          current_stage text not null,
          primary_actor_id text,
          canonical_case_id text,
          merged_into_case_id text,
          merge_state text,
          merge_updated_at text
        );
        create table if not exists case_relations (
          relation_id text primary key,
          left_case_id text not null,
          right_case_id text not null,
          relation_type text not null,
          score real not null,
          streak_count integer not null,
          status text not null,
          last_run_id text,
          last_reason text not null,
          supporting_alert_ids_json text not null,
          supporting_evidence_ids_json text not null,
          first_seen_at text not null,
          last_seen_at text not null,
          unique (left_case_id, right_case_id, relation_type)
        );
        create table if not exists case_merge_events (
          event_id text primary key,
          occurred_at text not null,
          run_id text,
          cluster_id text not null,
          old_canonical_case_id text,
          new_canonical_case_id text not null,
          affected_case_ids_json text not null,
          reason text not null,
          detail_json text not null
        );
        create table if not exists timeline_events (
          timeline_event_id text primary key,
          case_id text not null,
          occurred_at text not null,
          stage text not null,
          title text not null,
          related_alert_ids text not null,
          related_evidence_ids text not null
        );
        create table if not exists evidence (
          evidence_id text primary key,
          case_id text not null,
          occurred_at text,
          evidence_type text not null,
          summary text not null
        );
        create table if not exists intel_cache (
          indicator text not null,
          indicator_type text not null,
          verdict text not null,
          confidence real not null,
          queried_at text not null,
          primary key (indicator, indicator_type)
        );
        create table if not exists alert_ingest_events (
          event_id text primary key,
          alert_id text not null,
          source text not null,
          ingested_at text not null,
          processed_at text,
          trigger_state text not null
        );
        create table if not exists patrol_runs (
          run_id text primary key,
          trigger_source text not null,
          status text not null,
          summary text not null,
          started_at text not null,
          finished_at text,
          analysis_cutoff_at text not null
        );
        create table if not exists patrol_run_costs (
          run_id text primary key,
          trigger_source text not null,
          trigger_mode text not null,
          model text,
          status text not null,
          started_at text not null,
          finished_at text not null,
          duration_ms integer,
          turns integer,
          tool_calls integer,
          usage_input_tokens integer,
          usage_output_tokens integer,
          usage_cached_input_tokens integer,
          usage_total_tokens integer,
          recorded_at text not null
        );
        create table if not exists case_alert_links (
          case_id text not null,
          alert_id text not null,
          linked_at text not null,
          confidence real not null,
          reason text not null,
          is_active integer not null default 1,
          unlinked_at text,
          primary key (case_id, alert_id)
        );
        create table if not exists case_actor_profiles (
          case_actor_id text primary key,
          case_id text not null,
          label text not null,
          status text not null,
          profile_confidence real not null,
          risk_level text not null,
          is_primary integer not null default 0,
          current_stage text not null,
          first_seen_at text,
          last_seen_at text,
          summary text not null,
          created_at text not null,
          updated_at text not null
        );
        create table if not exists case_actor_observations (
          observation_id text primary key,
          case_actor_id text not null,
          observation_type text not null,
          observation_key text not null,
          observation_value text not null,
          confidence real not null,
          first_seen_at text,
          last_seen_at text,
          source_count integer not null default 1,
          created_at text not null,
          updated_at text not null
        );
        create table if not exists case_actor_links (
          link_id text primary key,
          case_actor_id text not null,
          target_type text not null,
          target_id text not null,
          link_confidence real not null,
          link_reason text not null,
          linked_at text not null
        );
        create table if not exists attacker_profiles (
          attacker_profile_id text primary key,
          label text not null,
          status text not null,
          profile_confidence real not null,
          risk_level text not null,
          summary text not null,
          first_seen_at text,
          last_seen_at text,
          created_at text not null,
          updated_at text not null
        );
        create table if not exists case_actor_profile_links (
          link_id text primary key,
          case_actor_id text not null,
          attacker_profile_id text not null,
          relation_status text not null,
          relation_score real not null,
          decision_reason text not null,
          created_at text not null
        );
        create table if not exists notification_outbox (
          notification_id text primary key,
          case_id text not null,
          channel text not null,
          template text not null,
          title text not null,
          body text not null,
          dedupe_key text not null,
          status text not null,
          created_at text not null,
          sent_at text
        );
        create table if not exists case_digests (
          case_id text primary key,
          digest_text text not null,
          facts_json text not null,
          updated_at text not null
        );
        create table if not exists patrol_state (
          state_key text primary key,
          state_value_json text not null,
          updated_at text not null
        );
        create table if not exists agent_outputs (
          output_id text primary key,
          occurred_at text not null,
          run_id text,
          source text not null,
          turn_index integer not null,
          response_id text,
          has_tool_calls integer not null,
          output_text text not null,
          usage_input_tokens integer not null,
          usage_output_tokens integer not null,
          usage_cached_input_tokens integer not null,
          meta_json text not null
        );
        create table if not exists agent_outputs_archive (
          output_id text primary key,
          occurred_at text not null,
          run_id text,
          source text not null,
          turn_index integer not null,
          response_id text,
          has_tool_calls integer not null,
          output_text text not null,
          usage_input_tokens integer not null,
          usage_output_tokens integer not null,
          usage_cached_input_tokens integer not null,
          meta_json text not null,
          archived_at text not null
        );
        create table if not exists agent_tool_calls (
          call_id text primary key,
          occurred_at text not null,
          run_id text,
          source text not null,
          tool_name text not null,
          payload_json text not null,
          result_ok integer not null,
          result_summary text not null,
          result_json text not null,
          latency_ms integer not null
        );
        create table if not exists agent_tool_calls_archive (
          call_id text primary key,
          occurred_at text not null,
          run_id text,
          source text not null,
          tool_name text not null,
          payload_json text not null,
          result_ok integer not null,
          result_summary text not null,
          result_json text not null,
          latency_ms integer not null,
          archived_at text not null
        );
        create table if not exists alert_decisions (
          decision_id text primary key,
          occurred_at text not null,
          run_id text,
          alert_id text not null,
          decision text not null,
          case_id text,
          confidence real,
          reason text not null,
          detail_json text not null
        );
        create table if not exists alert_decisions_archive (
          decision_id text primary key,
          occurred_at text not null,
          run_id text,
          alert_id text not null,
          decision text not null,
          case_id text,
          confidence real,
          reason text not null,
          detail_json text not null,
          archived_at text not null
        );
        create table if not exists link_decisions (
          decision_id text primary key,
          occurred_at text not null,
          run_id text,
          alert_id text not null,
          case_id text not null,
          link_confidence real not null,
          reason_summary text not null,
          positive_factors_json text not null,
          negative_factors_json text not null,
          uncertainties_json text not null,
          supporting_evidence_ids_json text not null,
          analysis_cutoff_at text
        );
        create table if not exists link_decisions_archive (
          decision_id text primary key,
          occurred_at text not null,
          run_id text,
          alert_id text not null,
          case_id text not null,
          link_confidence real not null,
          reason_summary text not null,
          positive_factors_json text not null,
          negative_factors_json text not null,
          uncertainties_json text not null,
          supporting_evidence_ids_json text not null,
          analysis_cutoff_at text,
          archived_at text not null
        );
        create table if not exists case_assessments (
          assessment_id text primary key,
          occurred_at text not null,
          run_id text,
          case_id text not null,
          risk_level text not null,
          assessment_confidence real,
          current_stage text not null,
          verdict text not null,
          reason_summary text not null,
          supporting_alert_ids_json text not null,
          supporting_evidence_ids_json text not null,
          analysis_cutoff_at text
        );
        create table if not exists entity_assessments (
          assessment_id text primary key,
          occurred_at text not null,
          run_id text,
          entity_type text not null,
          entity_key text not null,
          entity_label text not null,
          related_case_id text,
          risk_level text not null,
          assessment_confidence real not null,
          verdict text not null,
          reason_summary text not null,
          supporting_alert_ids_json text not null,
          supporting_evidence_ids_json text not null,
          first_seen_at text,
          last_seen_at text,
          analysis_cutoff_at text,
          is_current integer not null
        );
        create table if not exists case_changes (
          change_id text primary key,
          occurred_at text not null,
          run_id text,
          case_id text not null,
          action text not null,
          before_json text not null,
          after_json text not null,
          reason text not null
        );
        create table if not exists case_changes_archive (
          change_id text primary key,
          occurred_at text not null,
          run_id text,
          case_id text not null,
          action text not null,
          before_json text not null,
          after_json text not null,
          reason text not null,
          archived_at text not null
        );
        create table if not exists escalation_decisions (
          escalation_id text primary key,
          occurred_at text not null,
          run_id text,
          case_id text not null,
          triggered integer not null,
          channel text not null,
          template text not null,
          notification_id text,
          dedupe_key text not null,
          reason text not null,
          detail_json text not null
        );
        create table if not exists spike_round_runs (
          round_id text primary key,
          applied_at text not null
        );
        create table if not exists verify_spike_round_runs (
          round_id text primary key,
          applied_at text not null
        );
        """
    )
    conn.execute(
        """
        create unique index if not exists idx_entity_assessments_current_unique
        on entity_assessments(entity_type, entity_key, coalesce(related_case_id, ''))
        where is_current = 1
        """
    )
    conn.execute(
        """
        create index if not exists idx_entity_assessments_filter
        on entity_assessments(entity_type, risk_level, occurred_at desc)
        """
    )
    conn.execute(
        """
        create unique index if not exists idx_case_actor_profiles_primary
        on case_actor_profiles(case_id)
        where is_primary = 1
        """
    )
    conn.execute(
        """
        create index if not exists idx_case_actor_profiles_case
        on case_actor_profiles(case_id, status, updated_at desc)
        """
    )
    conn.execute(
        """
        create unique index if not exists idx_case_actor_observations_unique
        on case_actor_observations(case_actor_id, observation_type, observation_key)
        """
    )
    conn.execute(
        """
        create index if not exists idx_case_actor_links_target
        on case_actor_links(target_type, target_id)
        """
    )
    conn.execute(
        """
        create index if not exists idx_patrol_run_costs_started_at
        on patrol_run_costs(started_at desc)
        """
    )
    conn.execute(
        """
        create index if not exists idx_agent_outputs_run_time
        on agent_outputs(run_id, occurred_at desc)
        """
    )
    _ensure_alerts_shape(conn)
    _ensure_case_alert_links_shape(conn)
    _ensure_patrol_runs_shape(conn)
    _ensure_cases_convergence_shape(conn)
    _ensure_evidence_shape(conn)
    _ensure_verify_spike_round_runs_shape(conn)
    _backfill_case_links_from_legacy_alert_case_id(conn)
