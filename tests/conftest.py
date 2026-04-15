import pytest

from security_analyst_agent.bootstrap import bootstrap_spike_database, materialize_spike_runtime_demo
from security_analyst_agent.db import connect_db


@pytest.fixture
def db_conn(tmp_path):
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    materialize_spike_runtime_demo(db_path)
    conn = connect_db(db_path)
    yield conn
    conn.close()
