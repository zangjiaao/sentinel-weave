from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo
from security_analyst_agent.db import connect_db, create_schema


def test_bootstrap_loads_only_fact_tables(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    conn = connect_db(db_path)
    case_count = conn.execute("select count(*) from cases").fetchone()[0]
    alert_count = conn.execute("select count(*) from alerts").fetchone()[0]
    timeline_count = conn.execute("select count(*) from timeline_events").fetchone()[0]
    evidence_count = conn.execute("select count(*) from evidence").fetchone()[0]

    assert case_count == 0
    assert alert_count >= 3
    assert timeline_count == 0
    assert evidence_count == 0


def test_materialize_spike_runtime_demo_builds_attack_chain_from_tools(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)

    conn = connect_db(db_path)
    case = conn.execute(
        "select case_id, overall_severity, current_stage from cases where case_id = ?",
        ("case_demo_001",),
    ).fetchone()
    timeline_count = conn.execute("select count(*) from timeline_events where case_id = ?", ("case_demo_001",)).fetchone()[0]
    evidence_ids = [
        row["evidence_id"]
        for row in conn.execute(
            "select evidence_id from evidence where case_id = ? order by evidence_id asc",
            ("case_demo_001",),
        ).fetchall()
    ]

    assert case is not None
    assert case["overall_severity"] == "high"
    assert case["current_stage"] == "lateral_prep"
    assert timeline_count == 3
    assert evidence_ids == ["evi_shell_conn_01", "evi_webshell_01"]


def test_create_schema_backfills_case_links_from_legacy_alert_case_id(tmp_path) -> None:
    db_path = tmp_path / "legacy.db"
    conn = connect_db(db_path)
    conn.executescript(
        """
        create table alerts (
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
        create table case_alert_links (
          case_id text not null,
          alert_id text not null,
          linked_at text not null,
          confidence real not null,
          reason text not null,
          primary key (case_id, alert_id)
        );
        """
    )
    conn.execute(
        """
        insert into alerts (
          alert_id, case_id, occurred_at, title, status, severity, attack_stage, src_ip, dst_ip, asset_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alt_legacy_001",
            "case_legacy_001",
            "2026-04-14T10:00:00+08:00",
            "legacy alert row",
            "open",
            "medium",
            "recon",
            "198.51.100.1",
            "203.0.113.10",
            "asset_api_prod",
        ),
    )
    conn.commit()

    create_schema(conn)

    row = conn.execute(
        """
        select case_id, alert_id, is_active
        from case_alert_links
        where alert_id = ?
        """,
        ("alt_legacy_001",),
    ).fetchone()
    assert row["case_id"] == "case_legacy_001"
    assert row["is_active"] == 1
