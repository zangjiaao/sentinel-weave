import json

from typer.testing import CliRunner

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.cli import app


def test_cli_alert_fetch_returns_json(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    payload = json.dumps({"status": ["new", "open"], "limit": 5})
    result = runner.invoke(app, ["alert.fetch", "--db-path", str(db_path), "--payload", payload])
    body = json.loads(result.stdout)
    assert result.exit_code == 0
    assert body["ok"] is True
    assert "alerts" in body["data"]


def test_cli_all_core_tools_return_unified_shape(tmp_path) -> None:
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    runner = CliRunner()
    cases = [
        ("alert.fetch", {"status": ["open"], "limit": 2}),
        ("alert.detail", {"alert_id": "alt_day2_webshell_01"}),
        ("asset.search", {"indicators": ["203.0.113.10"]}),
        ("case.get", {"case_id": "case_demo_001"}),
        ("case.timeline", {"case_id": "case_demo_001", "include_evidence": True}),
        ("case.explain-link", {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_day3_shell_01"}),
        ("intel.lookup", {"indicator": "198.51.100.23", "indicator_type": "ip"}),
        ("notify.preview", {"case_id": "case_demo_001", "channel": "feishu", "template": "high_risk_case_brief"}),
        ("report.draft", {"case_id": "case_demo_001", "template": "incident_report_v1", "tone": "professional"}),
    ]
    required_keys = {"ok", "summary", "data", "warnings", "refs", "page", "meta"}

    for tool_name, payload in cases:
        result = runner.invoke(
            app,
            [tool_name, "--db-path", str(db_path), "--payload", json.dumps(payload, ensure_ascii=False)],
        )
        assert result.exit_code == 0
        body = json.loads(result.stdout)
        assert required_keys.issubset(body.keys())
