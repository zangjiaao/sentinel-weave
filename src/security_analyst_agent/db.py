from pathlib import Path
import sqlite3


def connect_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


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
          case_id text,
          occurred_at text not null,
          title text not null,
          status text not null,
          severity text not null,
          attack_stage text not null,
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
          primary_actor_id text
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
        """
    )

