from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db, create_schema


def test_bootstrap_loads_attack_chain(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    conn = connect_db(db_path)
    case_count = conn.execute("select count(*) from cases").fetchone()[0]
    alert_count = conn.execute("select count(*) from alerts").fetchone()[0]

    assert case_count == 1
    assert alert_count >= 3


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
