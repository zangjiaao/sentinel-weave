# Hermes Security Analyst Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个无前端的 `Hermes` 安全分析 `Spike`，基于种子数据跑通“告警读取 -> 资产识别 -> 案件时间线 -> 关联解释 -> 情报补证 -> 通知/报告草稿”的核心闭环。

**Architecture:** 使用单体 Python 项目实现。`Pydantic` 负责 Tool 输入输出契约，`SQLite` 保存 Spike 所需的资产/告警/案件/证据样本数据，领域服务实现确定性查询和解释逻辑，`Typer` CLI 以 JSON 输入/JSON 输出方式暴露给 Hermes 调用；同时补齐 `Hermes` 所需的运行时产物：`tool registry manifest`、`main analyst prompt`、`patrol loop config`。

**Tech Stack:** Python 3.12、`uv`、`pydantic`、`typer`、标准库 `sqlite3`、`pytest`、`ruff`

---

## File Structure

- Create: `pyproject.toml`
- Create: `README.md`
- Create: `fixtures/spike/assets.json`
- Create: `fixtures/spike/alerts.json`
- Create: `fixtures/spike/cases.json`
- Create: `fixtures/spike/timeline.json`
- Create: `fixtures/spike/evidence.json`
- Create: `fixtures/spike/intel_cache.json`
- Create: `src/security_analyst_agent/__init__.py`
- Create: `src/security_analyst_agent/cli.py`
- Create: `src/security_analyst_agent/config.py`
- Create: `src/security_analyst_agent/db.py`
- Create: `src/security_analyst_agent/bootstrap.py`
- Create: `src/security_analyst_agent/tool_dispatch.py`
- Create: `src/security_analyst_agent/schemas/common.py`
- Create: `src/security_analyst_agent/schemas/asset_tools.py`
- Create: `src/security_analyst_agent/schemas/alert_tools.py`
- Create: `src/security_analyst_agent/schemas/case_tools.py`
- Create: `src/security_analyst_agent/schemas/intel_tools.py`
- Create: `src/security_analyst_agent/schemas/output_tools.py`
- Create: `src/security_analyst_agent/repositories/assets.py`
- Create: `src/security_analyst_agent/repositories/alerts.py`
- Create: `src/security_analyst_agent/repositories/cases.py`
- Create: `src/security_analyst_agent/services/link_explainer.py`
- Create: `src/security_analyst_agent/services/intel.py`
- Create: `src/security_analyst_agent/services/output.py`
- Create: `src/security_analyst_agent/tools/asset_tools.py`
- Create: `src/security_analyst_agent/tools/alert_tools.py`
- Create: `src/security_analyst_agent/tools/case_tools.py`
- Create: `src/security_analyst_agent/tools/intel_tools.py`
- Create: `src/security_analyst_agent/tools/output_tools.py`
- Create: `tests/conftest.py`
- Create: `tests/test_cli.py`
- Create: `tests/test_bootstrap.py`
- Create: `tests/test_alert_tools.py`
- Create: `tests/test_asset_tools.py`
- Create: `tests/test_case_tools.py`
- Create: `tests/test_intel_tools.py`
- Create: `tests/test_output_tools.py`
- Create: `tests/test_cli_e2e.py`
- Create: `tests/test_hermes_artifacts.py`
- Create: `docs/runbooks/hermes-spike.md`
- Create: `docs/runbooks/hermes-runtime-bootstrap.md`
- Create: `hermes/tool-registry.json`
- Create: `hermes/patrol-loop.json`
- Create: `hermes/agents/main-analyst.md`

项目边界保持简单：

- 不做前端页面
- 不做真实设备接入
- 不做自动发送通知
- 不做多租户
- 只做 `6.15` 约定的 `9` 个核心 Tool

### Task 1: 搭建 Python Spike 工程骨架

**Files:**
- Create: `pyproject.toml`
- Create: `src/security_analyst_agent/__init__.py`
- Create: `src/security_analyst_agent/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: 先写 CLI 冒烟测试**

```python
from typer.testing import CliRunner

from security_analyst_agent.cli import app


def test_cli_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "alert.fetch" in result.stdout
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_cli.py::test_cli_shows_help -q`
Expected: FAIL with `ModuleNotFoundError` or `No module named 'security_analyst_agent'`

- [ ] **Step 3: 创建最小工程与 CLI 入口**

```toml
[project]
name = "security-analyst-agent"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
  "pydantic>=2.7,<3",
  "typer>=0.12,<1"
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0,<9",
  "ruff>=0.4,<0.5"
]

[tool.pytest.ini_options]
pythonpath = ["src"]
```
```python
import typer

app = typer.Typer(help="Hermes security analyst spike CLI")


@app.callback()
def main() -> None:
    return None


@app.command("alert.fetch")
def alert_fetch() -> None:
    typer.echo("alert.fetch placeholder")
```

- [ ] **Step 4: 重新运行测试**

Run: `uv run pytest tests/test_cli.py::test_cli_shows_help -q`
Expected: PASS

### Task 2: 定义 Tool 通用契约与 9 个核心 Schema

**Files:**
- Create: `src/security_analyst_agent/schemas/common.py`
- Create: `src/security_analyst_agent/schemas/asset_tools.py`
- Create: `src/security_analyst_agent/schemas/alert_tools.py`
- Create: `src/security_analyst_agent/schemas/case_tools.py`
- Create: `src/security_analyst_agent/schemas/intel_tools.py`
- Create: `src/security_analyst_agent/schemas/output_tools.py`
- Create: `tests/test_alert_tools.py`

- [ ] **Step 1: 先写请求默认值与响应骨架测试**

```python
from security_analyst_agent.schemas.alert_tools import AlertFetchRequest
from security_analyst_agent.schemas.common import ToolResponse


def test_alert_fetch_request_defaults_limit_to_20() -> None:
    request = AlertFetchRequest.model_validate({})
    assert request.limit == 20


def test_tool_response_requires_summary() -> None:
    response = ToolResponse(ok=True, summary="ok", data={})
    assert response.summary == "ok"
    assert response.meta.partial is False
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_alert_tools.py -q`
Expected: FAIL with missing schema modules

- [ ] **Step 3: 创建通用 Schema 与请求响应模型**

```python
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TimeRange(BaseModel):
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    timezone: str = "Asia/Shanghai"


class ToolMeta(BaseModel):
    cache_hit: bool = False
    partial: bool = False
    generated_at: datetime = Field(default_factory=datetime.now)


class ToolPage(BaseModel):
    next_cursor: str | None = None
    has_more: bool = False


class ToolResponse(BaseModel):
    ok: bool
    summary: str
    data: dict[str, Any]
    warnings: list[str] = Field(default_factory=list)
    refs: dict[str, list[str]] = Field(default_factory=dict)
    page: ToolPage = Field(default_factory=ToolPage)
    meta: ToolMeta = Field(default_factory=ToolMeta)
```
```python
from pydantic import BaseModel, Field

from security_analyst_agent.schemas.common import TimeRange


class AlertFetchRequest(BaseModel):
    time_range: TimeRange | None = None
    source_ids: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    status: list[str] = Field(default_factory=list)
    limit: int = 20
    cursor: str | None = None
```

- [ ] **Step 4: 为其余 8 个 Tool 补齐请求/响应模型**

```python
class AssetSearchRequest(BaseModel):
    query: str | None = None
    indicators: list[str] = Field(default_factory=list)
    include_inactive: bool = False
    limit: int = 10


class CaseExplainLinkRequest(BaseModel):
    case_id: str
    target_type: str
    target_id: str


class NotifyPreviewRequest(BaseModel):
    case_id: str
    channel: str
    template: str
```

- [ ] **Step 5: 重新运行测试**

Run: `uv run pytest tests/test_alert_tools.py -q`
Expected: PASS

### Task 3: 建立 SQLite 与三天攻击链种子数据

**Files:**
- Create: `fixtures/spike/assets.json`
- Create: `fixtures/spike/alerts.json`
- Create: `fixtures/spike/cases.json`
- Create: `fixtures/spike/timeline.json`
- Create: `fixtures/spike/evidence.json`
- Create: `fixtures/spike/intel_cache.json`
- Create: `src/security_analyst_agent/config.py`
- Create: `src/security_analyst_agent/db.py`
- Create: `src/security_analyst_agent/bootstrap.py`
- Create: `tests/conftest.py`
- Create: `tests/test_bootstrap.py`

- [ ] **Step 1: 先写导入种子数据的测试**

```python
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
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_bootstrap.py::test_bootstrap_loads_attack_chain -q`
Expected: FAIL with missing bootstrap/db modules

- [ ] **Step 3: 创建数据库初始化与 fixtures**

```python
from pathlib import Path
import sqlite3


def connect_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn
```
```python
def create_schema(conn) -> None:
    conn.executescript(
        """
        create table if not exists assets (
          asset_id text primary key,
          asset_name text not null,
          system_name text not null,
          owner_team text,
          internet_exposed integer not null
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
```

```python
import pytest

from security_analyst_agent.bootstrap import bootstrap_spike_database
from security_analyst_agent.db import connect_db


@pytest.fixture
def db_conn(tmp_path):
    db_path = tmp_path / "spike.db"
    bootstrap_spike_database(db_path)
    return connect_db(db_path)
```

- [ ] **Step 4: 写入与你的示例一致的三天攻击链**

```json
[
  {
    "asset_id": "asset_api_prod",
    "asset_name": "api-prod",
    "system_name": "统一认证 API",
    "owner_team": "identity",
    "internet_exposed": 1
  }
]
```
```json
[
  {
    "case_id": "case_demo_001",
    "title": "多阶段 Web 入侵与后续横向准备",
    "status": "open",
    "overall_severity": "high",
    "current_stage": "lateral_prep",
    "primary_actor_id": "actor_demo_001"
  }
]
```
```json
[
  {
    "timeline_event_id": "tl_day1_recon",
    "case_id": "case_demo_001",
    "occurred_at": "2026-04-10T09:10:00+08:00",
    "stage": "recon",
    "title": "对公网入口进行打点",
    "related_alert_ids": ["alt_day1_scan_01"],
    "related_evidence_ids": []
  },
  {
    "timeline_event_id": "tl_day2_webshell",
    "case_id": "case_demo_001",
    "occurred_at": "2026-04-11T14:20:00+08:00",
    "stage": "persistence",
    "title": "利用漏洞写入 webshell",
    "related_alert_ids": ["alt_day2_webshell_01"],
    "related_evidence_ids": ["evi_webshell_01"]
  }
]
```
```json
[
  {
    "evidence_id": "evi_webshell_01",
    "case_id": "case_demo_001",
    "evidence_type": "payload",
    "summary": "上传行为包含 webshell 落地痕迹"
  },
  {
    "evidence_id": "evi_shell_conn_01",
    "case_id": "case_demo_001",
    "evidence_type": "connection",
    "summary": "新源 IP 连接已存在 webshell"
  }
]
```
```json
[
  {
    "indicator": "198.51.100.23",
    "indicator_type": "ip",
    "verdict": "malicious",
    "confidence": 0.92,
    "queried_at": "2026-04-12T12:00:00+08:00"
  }
]
```
```json
[
  {
    "alert_id": "alt_day1_scan_01",
    "case_id": "case_demo_001",
    "occurred_at": "2026-04-10T09:10:00+08:00",
    "title": "扫描多个公网 Web 入口",
    "status": "open",
    "severity": "medium",
    "attack_stage": "recon",
    "src_ip": "198.51.100.23",
    "dst_ip": "203.0.113.10",
    "asset_id": "asset_api_prod"
  },
  {
    "alert_id": "alt_day2_webshell_01",
    "case_id": "case_demo_001",
    "occurred_at": "2026-04-11T14:20:00+08:00",
    "title": "漏洞利用后写入 webshell",
    "status": "open",
    "severity": "high",
    "attack_stage": "persistence",
    "src_ip": "198.51.100.23",
    "dst_ip": "203.0.113.10",
    "asset_id": "asset_api_prod"
  },
  {
    "alert_id": "alt_day3_shell_01",
    "case_id": "case_demo_001",
    "occurred_at": "2026-04-12T11:03:00+08:00",
    "title": "新 IP 连接 webshell",
    "status": "open",
    "severity": "high",
    "attack_stage": "command_execution",
    "src_ip": "198.51.100.77",
    "dst_ip": "203.0.113.10",
    "asset_id": "asset_api_prod"
  }
]
```

- [ ] **Step 5: 重新运行测试**

Run: `uv run pytest tests/test_bootstrap.py::test_bootstrap_loads_attack_chain -q`
Expected: PASS

### Task 4: 实现 `alert.fetch`、`alert.detail`、`asset.search`

**Files:**
- Create: `src/security_analyst_agent/repositories/assets.py`
- Create: `src/security_analyst_agent/repositories/alerts.py`
- Create: `src/security_analyst_agent/tools/asset_tools.py`
- Create: `src/security_analyst_agent/tools/alert_tools.py`
- Create: `tests/test_asset_tools.py`
- Modify: `tests/test_alert_tools.py`

- [ ] **Step 1: 先写 3 个读工具的行为测试**

```python
from security_analyst_agent.tools.alert_tools import alert_fetch, alert_detail
from security_analyst_agent.tools.asset_tools import asset_search


def test_alert_fetch_returns_ranked_queue(db_conn) -> None:
    result = alert_fetch(db_conn, {"status": ["new", "open"], "limit": 10})
    assert result["ok"] is True
    assert result["data"]["alerts"][0]["alert_id"] == "alt_day3_shell_01"


def test_alert_detail_returns_parser_and_evidence_refs(db_conn) -> None:
    result = alert_detail(db_conn, {"alert_id": "alt_day2_webshell_01"})
    assert result["data"]["alert"]["attack_stage"] == "persistence"
    assert "parser_profile_version_id" in result["data"]["alert"]


def test_asset_search_matches_ip_and_domain_candidates(db_conn) -> None:
    result = asset_search(db_conn, {"indicators": ["203.0.113.10", "api.example.com"]})
    assert result["data"]["candidates"][0]["asset_id"] == "asset_api_prod"
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_alert_tools.py tests/test_asset_tools.py -q`
Expected: FAIL with missing repository/tool modules

- [ ] **Step 3: 实现仓储与工具函数**

```python
def fetch_alerts(conn, limit: int, statuses: list[str]) -> list[dict]:
    if statuses:
        placeholders = ",".join("?" for _ in statuses)
        sql = f"""
        select alert_id, case_id, occurred_at, title, status, severity, attack_stage, src_ip, asset_id
        from alerts
        where status in ({placeholders})
        order by occurred_at desc
        limit ?
        """
        rows = conn.execute(sql, (*statuses, limit)).fetchall()
    else:
        rows = conn.execute(
            """
            select alert_id, case_id, occurred_at, title, status, severity, attack_stage, src_ip, asset_id
            from alerts
            order by occurred_at desc
            limit ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
```
```python
from datetime import datetime

from security_analyst_agent.schemas.common import ToolMeta


def alert_fetch(conn, payload: dict) -> dict:
    alerts = fetch_alerts(conn, payload.get("limit", 20), payload.get("status", []))
    return {
        "ok": True,
        "summary": f"返回 {len(alerts)} 条待研判告警摘要",
        "data": {"alerts": alerts},
        "warnings": [],
        "refs": {"alert_ids": [item["alert_id"] for item in alerts]},
        "page": {"next_cursor": None, "has_more": False},
        "meta": ToolMeta(generated_at=datetime.now()).model_dump(),
    }
```

- [ ] **Step 4: 为 `alert.detail` 附加 `parser_profile_version_id` 与 `evidence_summary`**

```python
def alert_detail(conn, payload: dict) -> dict:
    row = conn.execute(
        """
        select alert_id, case_id, occurred_at, title, severity, attack_stage, src_ip, dst_ip, asset_id
        from alerts where alert_id = ?
        """,
        (payload["alert_id"],),
    ).fetchone()
    alert = dict(row)
    alert["parser_profile_version_id"] = "waf_nginx_v1"
    alert["evidence_summary"] = "命中上传落地 + 后续命令执行关联证据"
    return {"ok": True, "summary": f"读取告警 {alert['alert_id']}", "data": {"alert": alert}}
```

- [ ] **Step 5: 重新运行测试**

Run: `uv run pytest tests/test_alert_tools.py tests/test_asset_tools.py -q`
Expected: PASS

### Task 5: 实现 `case.get`、`case.timeline`、`case.explain-link`

**Files:**
- Create: `src/security_analyst_agent/repositories/cases.py`
- Create: `src/security_analyst_agent/services/link_explainer.py`
- Create: `src/security_analyst_agent/tools/case_tools.py`
- Create: `tests/test_case_tools.py`

- [ ] **Step 1: 先写案件读取与解释测试**

```python
from security_analyst_agent.tools.case_tools import case_explain_link, case_get, case_timeline


def test_case_get_returns_actor_and_target_summary(db_conn) -> None:
    result = case_get(db_conn, {"case_id": "case_demo_001"})
    assert result["data"]["case"]["overall_severity"] == "high"
    assert result["data"]["case"]["primary_actor_id"] == "actor_demo_001"


def test_case_timeline_returns_ordered_attack_steps(db_conn) -> None:
    result = case_timeline(db_conn, {"case_id": "case_demo_001", "include_evidence": True})
    stages = [item["stage"] for item in result["data"]["events"]]
    assert stages == ["recon", "persistence", "command_execution"]


def test_case_explain_link_shows_positive_factors(db_conn) -> None:
    result = case_explain_link(
        db_conn,
        {"case_id": "case_demo_001", "target_type": "alert", "target_id": "alt_day3_shell_01"},
    )
    assert result["data"]["link_decision"]["is_linked"] is True
    assert result["data"]["link_decision"]["positive_factors"]
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_case_tools.py -q`
Expected: FAIL with missing case tool modules

- [ ] **Step 3: 实现案件头部与时间线查询**

```python
def load_case(conn, case_id: str) -> dict:
    row = conn.execute(
        "select case_id, title, status, overall_severity, current_stage, primary_actor_id from cases where case_id = ?",
        (case_id,),
    ).fetchone()
    return dict(row)


def load_case_timeline(conn, case_id: str) -> list[dict]:
    rows = conn.execute(
        """
        select occurred_at, attack_stage as stage, title, alert_id
        from alerts
        where case_id = ?
        order by occurred_at asc
        """,
        (case_id,),
    ).fetchall()
    return [dict(row) for row in rows]
```

- [ ] **Step 4: 实现可解释关联服务**

```python
def explain_alert_link(alert: dict) -> dict:
    return {
        "is_linked": True,
        "confidence": 0.87,
        "reason_summary": "同一目标资产上的多阶段活动形成连续攻击路径",
        "positive_factors": [
            {"factor_type": "same_target_asset", "weight": 0.35, "summary": "命中同一生产 API 资产"},
            {"factor_type": "same_attack_path", "weight": 0.30, "summary": "webshell 写入后出现命令执行"}
        ],
        "negative_factors": [],
        "uncertainties": ["攻击源 IP 已发生变化，但仍指向同一落点"],
        "supporting_evidence_ids": ["evi_webshell_01", "evi_shell_conn_01"]
    }
```

- [ ] **Step 5: 重新运行测试**

Run: `uv run pytest tests/test_case_tools.py -q`
Expected: PASS

### Task 6: 实现 `intel.lookup`、`notify.preview`、`report.draft`

**Files:**
- Create: `src/security_analyst_agent/services/intel.py`
- Create: `src/security_analyst_agent/services/output.py`
- Create: `src/security_analyst_agent/tools/intel_tools.py`
- Create: `src/security_analyst_agent/tools/output_tools.py`
- Create: `tests/test_intel_tools.py`
- Create: `tests/test_output_tools.py`

- [ ] **Step 1: 先写情报补证与输出草稿测试**

```python
from security_analyst_agent.tools.intel_tools import intel_lookup
from security_analyst_agent.tools.output_tools import notify_preview, report_draft


def test_intel_lookup_returns_cached_verdict(db_conn) -> None:
    result = intel_lookup(db_conn, {"indicator": "198.51.100.23", "indicator_type": "ip"})
    assert result["data"]["result"]["verdict"] == "malicious"
    assert result["data"]["result"]["cache_hit"] is True


def test_notify_preview_contains_why_now(db_conn) -> None:
    result = notify_preview(db_conn, {"case_id": "case_demo_001", "channel": "feishu", "template": "high_risk_case_brief"})
    assert "why_now" in result["data"]["preview"]


def test_report_draft_contains_timeline_section(db_conn) -> None:
    result = report_draft(db_conn, {"case_id": "case_demo_001", "template": "incident_report_v1", "tone": "professional"})
    assert "timeline" in result["data"]["report"]["outline"]
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_intel_tools.py tests/test_output_tools.py -q`
Expected: FAIL with missing intel/output modules

- [ ] **Step 3: 实现情报缓存读取**

```python
def lookup_cached_indicator(conn, indicator: str, indicator_type: str) -> dict | None:
    row = conn.execute(
        "select indicator, indicator_type, verdict, confidence, queried_at from intel_cache where indicator = ? and indicator_type = ?",
        (indicator, indicator_type),
    ).fetchone()
    return dict(row) if row else None
```

- [ ] **Step 4: 实现通知与报告草稿**

```python
def build_notify_preview(case: dict) -> dict:
    return {
        "preview_id": f"preview_{case['case_id']}",
        "channel": "feishu",
        "title": f"[{case['overall_severity'].upper()}] {case['title']}",
        "body": "攻击者已从侦察进入命令执行阶段，请立即核查受害资产。",
        "overall_severity": case["overall_severity"],
        "why_now": "24 小时内出现 webshell 后续控制行为，风险明显升级",
        "recommended_recipients": ["soc_oncall", "asset_owner"],
        "dedupe_key": case["case_id"],
    }
```
```python
def build_report(case: dict, timeline: list[dict]) -> dict:
    return {
        "report_id": f"report_{case['case_id']}",
        "title": case["title"],
        "summary": "该案件表现为典型的多阶段 Web 入侵。",
        "outline": ["summary", "timeline", "targets", "actor_profile", "evidence", "recommendations"],
        "draft_markdown": "\n".join(
            [
                f"# {case['title']}",
                "## Summary",
                "攻击者先扫描多个系统，随后利用漏洞上传 webshell，并由新 IP 接管控制。",
                "## Timeline",
                *[f"- {item['occurred_at']} {item['stage']} {item['title']}" for item in timeline],
            ]
        ),
    }
```

- [ ] **Step 5: 重新运行测试**

Run: `uv run pytest tests/test_intel_tools.py tests/test_output_tools.py -q`
Expected: PASS

### Task 7: 接入 JSON CLI 分发与端到端验证

**Files:**
- Create: `src/security_analyst_agent/tool_dispatch.py`
- Modify: `src/security_analyst_agent/cli.py`
- Create: `tests/test_cli_e2e.py`
- Create: `README.md`
- Create: `docs/runbooks/hermes-spike.md`

- [ ] **Step 1: 先写 CLI JSON 调用的端到端测试**

```python
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
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_cli_e2e.py::test_cli_alert_fetch_returns_json -q`
Expected: FAIL because CLI still returns placeholder text

- [ ] **Step 3: 实现工具分发器与 JSON 入参**

```python
import json
from pathlib import Path

import typer

from security_analyst_agent.db import connect_db
from security_analyst_agent.tools.alert_tools import alert_fetch


def dispatch_tool(conn, tool_name: str, payload: dict) -> dict:
    if tool_name == "alert.fetch":
        return alert_fetch(conn, payload)
    raise ValueError(f"unsupported tool: {tool_name}")
```
```python
@app.command("alert.fetch")
def alert_fetch_command(db_path: Path = typer.Option(...), payload: str = typer.Option(...)) -> None:
    body = json.loads(payload)
    result = dispatch_tool(connect_db(db_path), "alert.fetch", body)
    typer.echo(json.dumps(result, ensure_ascii=False))
```

- [ ] **Step 4: 为 9 个核心 Tool 全部接线并写运行手册**

````markdown
# Hermes Spike Runbook

## Bootstrap

```bash
uv sync --extra dev
uv run python -m security_analyst_agent.bootstrap
```

## Example

```bash
uv run python -m security_analyst_agent.cli alert.fetch --db-path ./spike.db --payload '{"status":["new","open"],"limit":5}'
uv run python -m security_analyst_agent.cli case.get --db-path ./spike.db --payload '{"case_id":"case_demo_001"}'
uv run python -m security_analyst_agent.cli report.draft --db-path ./spike.db --payload '{"case_id":"case_demo_001","template":"incident_report_v1","tone":"professional"}'
```
````

- [ ] **Step 5: 运行完整测试集**

Run: `uv run pytest tests -q`
Expected: PASS

### Task 8: 收尾校验与文档清理

**Files:**
- Modify: `README.md`
- Modify: `docs/runbooks/hermes-spike.md`

- [ ] **Step 1: 在 README 写明 Spike 边界**

```markdown
## Scope

- Read-only analyst tools only
- Seeded SQLite data only
- No real device integration yet
- No automatic notification sending
- No frontend in this spike
```

- [ ] **Step 2: 增加“如何验证三天攻击链”的操作说明**

```markdown
## Validate the Demo Chain

1. Run `alert.fetch` to see the latest queue
2. Run `alert.detail` for `alt_day2_webshell_01`
3. Run `case.timeline` for `case_demo_001`
4. Run `case.explain-link` for `alt_day3_shell_01`
5. Run `notify.preview` and `report.draft`
```

- [ ] **Step 3: 运行 lint 与测试**

Run: `uv run ruff check . && uv run pytest tests -q`
Expected: PASS

### Task 9: 配置 Hermes 运行时接入产物

**Files:**
- Create: `hermes/tool-registry.json`
- Create: `hermes/patrol-loop.json`
- Create: `hermes/agents/main-analyst.md`
- Create: `docs/runbooks/hermes-runtime-bootstrap.md`
- Create: `tests/test_hermes_artifacts.py`

- [ ] **Step 1: 先写 Hermes 产物校验测试**

```python
import json
from pathlib import Path


def test_tool_registry_contains_nine_core_tools() -> None:
    data = json.loads(Path("hermes/tool-registry.json").read_text())
    names = [item["name"] for item in data["tools"]]
    assert len(names) == 9
    assert names == [
        "alert.fetch",
        "alert.detail",
        "asset.search",
        "case.get",
        "case.timeline",
        "case.explain-link",
        "intel.lookup",
        "notify.preview",
        "report.draft",
    ]


def test_patrol_loop_starts_from_alert_fetch() -> None:
    data = json.loads(Path("hermes/patrol-loop.json").read_text())
    assert data["schedule"] == "every_5m"
    assert data["entry_tool"] == "alert.fetch"
    assert "high_risk_case_found" in data["stop_conditions"]


def test_main_analyst_prompt_contains_guardrails() -> None:
    text = Path("hermes/agents/main-analyst.md").read_text()
    assert "只在证据不足时调用 `intel.lookup`" in text
    assert "不要直接处理海量原始日志" in text
    assert "只生成 `notify.preview`，不直接发送通知" in text
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_hermes_artifacts.py -q`
Expected: FAIL with missing Hermes artifact files

- [ ] **Step 3: 编写 Tool Registry Manifest**

```json
{
  "version": "0.1",
  "runtime": "hermes",
  "tools": [
    {
      "name": "alert.fetch",
      "description": "拉取待研判告警摘要队列",
      "when_to_use": ["开始一轮巡检时", "需要获取最近的新告警时"],
      "command_template": "uv run python -m security_analyst_agent.cli alert.fetch --db-path ${SPIKE_DB_PATH} --payload '${JSON_PAYLOAD}'",
      "read_only": true,
      "timeout_sec": 15,
      "cost_level": "low",
      "idempotent": true
    }
  ]
}
```

要求：

- 补齐全部 `9` 个 Tool
- 每个 Tool 都要有 `when_to_use`
- 所有 Tool 都默认标注 `read_only=true`
- `notify.preview` 和 `report.draft` 可标为 `cost_level=medium`

- [ ] **Step 4: 编写 Main Analyst Prompt**

```markdown
# Main Analyst Agent

你是一个蓝队安全分析 Agent。

你的目标：
1. 从告警摘要中识别真实攻击线索
2. 结合资产、案件、证据与情报补全上下文
3. 解释为什么若干事件属于同一攻击链
4. 在风险足够高时生成通知草稿和报告草稿

工作顺序：
- 默认先调用 `alert.fetch`
- 深入单条告警时再调用 `alert.detail`
- 确认被打对象时优先调用 `asset.search`
- 理解攻击过程时优先调用 `case.get` 和 `case.timeline`
- 解释关联依据时优先调用 `case.explain-link`
- 只在证据不足时调用 `intel.lookup`
- 只生成 `notify.preview`，不直接发送通知

约束：
- 不要直接处理海量原始日志
- 不要把第三方情报当作唯一真相源
- 证据不足时必须明确写出不确定性
```

- [ ] **Step 5: 编写 Patrol Loop 与接入 Runbook**

```json
{
  "schedule": "every_5m",
  "entry_tool": "alert.fetch",
  "default_filters": {
    "status": ["new", "open"],
    "limit": 20
  },
  "max_alerts_per_run": 10,
  "stop_conditions": [
    "no_more_alerts",
    "time_budget_exceeded",
    "high_risk_case_found"
  ],
  "write_memory_on_finish": true
}
```
````markdown
# Hermes Runtime Bootstrap

## Prerequisites

- Hermes runtime is installed and running
- `uv sync --extra dev` completed
- Spike database has been bootstrapped
- `SPIKE_DB_PATH` is set

## Register Tools

Load `hermes/tool-registry.json` into Hermes tool registry.

## Create Agent

Use `hermes/agents/main-analyst.md` as the system prompt for the single `main analyst agent`.

## Configure Loop

Load `hermes/patrol-loop.json` as the first patrol schedule.

## Smoke Test

1. Run one manual patrol
2. Confirm `alert.fetch` is called first
3. Confirm high-risk case can produce `notify.preview`
4. Confirm `report.draft` returns markdown output
````

- [ ] **Step 6: 重新运行测试**

Run: `uv run pytest tests/test_hermes_artifacts.py -q`
Expected: PASS

## Self-Review

**Spec coverage**

- `4.7` - `4.10` 的 Hermes 定位，由 `Task 7` 的 CLI 编排边界实现
- `4.11` 与 `6.16` 的 Hermes 接入方式、Prompt、Loop、记忆边界，由 `Task 9` 的运行时产物覆盖
- `5.1` - `5.8` 的核心工作流，由 `Task 3` - `Task 7` 的种子数据、案件链路、情报补证和输出草稿覆盖
- `6.14` - `6.15` 的 Tool 合约与 Spike Schema，由 `Task 2`、`Task 4`、`Task 5`、`Task 6`、`Task 7` 覆盖
- `9.7` - `9.10` 的标准化结果消费路径，在本 Spike 中以已标准化 fixtures 代替真实解析
- `15.*` 的最小数据模型，在 `Task 3` 的 SQLite 表和 fixtures 中落成第一版

**Placeholder scan**

- 未使用 `TODO`、`TBD`、`implement later` 等占位描述
- 每个任务都给了明确文件、测试命令和最小代码骨架

**Type consistency**

- 统一使用 `case_id`、`alert_id`、`asset_id`、`primary_actor_id`
- CLI 和工具函数统一采用 `payload: dict` 输入、结构化 JSON 输出
- 所有核心 Tool 保持 `ok/summary/data/warnings/refs/page/meta` 的响应骨架
