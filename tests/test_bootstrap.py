from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db


def test_bootstrap_loads_attack_chain(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)

    conn = connect_db(db_path)
    case_count = conn.execute("select count(*) from cases").fetchone()[0]
    alert_count = conn.execute("select count(*) from alerts").fetchone()[0]

    assert case_count == 1
    assert alert_count >= 3
