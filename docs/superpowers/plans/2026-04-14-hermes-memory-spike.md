# Hermes Memory Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一套可重复的 `Hermes` 长期记忆验证基线：使用基础种子 + 6 轮增量告警批次 + 噪音 + 次要干扰案件，验证 `Hermes memory` 是否真的能帮助持续巡检。

**Architecture:** 不扩展现有核心 Tool 合约，也不让 `Hermes` 直接写案件主事实。实现重点放在 `fixtures/spike_memory` 的轮次数据、一个独立的增量导入模块 `security_analyst_agent.memory_spike`、以及人工可执行的 `Hermes` 巡检 runbook。数据库继续作为事实源，只新增一张 `spike_round_runs` 表记录哪些轮次已经被应用。

**Tech Stack:** Python 3.12、`uv`、标准库 `argparse/json/sqlite3`、现有 `sqlite` schema、`pytest`

---

## File Structure

- Create: `fixtures/spike_memory/base_bundle.json`
- Create: `fixtures/spike_memory/rounds.json`
- Create: `src/security_analyst_agent/memory_spike.py`
- Create: `tests/test_memory_spike.py`
- Create: `docs/runbooks/hermes-memory-spike.md`
- Modify: `src/security_analyst_agent/config.py`
- Modify: `src/security_analyst_agent/db.py`
- Modify: `tests/test_hermes_artifacts.py`

边界要求：

- 不改现有 `9` 个核心 Tool 合约
- 不新增 `case` 写 Tool
- 不改 `Hermes` Skill 主流程
- 只增加 Spike 自己的 fixture / 导入 / 手册 / 测试能力

### Task 1: 定义 Memory Spike 轮次契约并先写失败测试

**Files:**
- Create: `tests/test_memory_spike.py`
- Modify: `src/security_analyst_agent/db.py`
- Create: `src/security_analyst_agent/memory_spike.py`

- [ ] **Step 1: 先写 Memory Spike 契约测试**

```python
import json
import subprocess
import sys

import pytest

from security_analyst_agent.db import connect_db
from security_analyst_agent.memory_spike import (
    apply_memory_spike_round,
    bootstrap_memory_spike_database,
    load_memory_spike_rounds,
)


def test_load_memory_spike_rounds_returns_six_rounds() -> None:
    rounds = load_memory_spike_rounds()
    assert [item["round_id"] for item in rounds] == [
        "round_01_recon",
        "round_02_exploit",
        "round_03_new_ip",
        "round_04_lateral_prep",
        "round_05_silent_period",
        "round_06_reactivation",
    ]


def test_bootstrap_memory_spike_loads_base_bundle(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    conn = connect_db(db_path)
    assert conn.execute("select count(*) from assets").fetchone()[0] == 3
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 0
    assert conn.execute("select count(*) from cases").fetchone()[0] == 0
    assert conn.execute("select count(*) from spike_round_runs").fetchone()[0] == 0


def test_apply_memory_spike_rounds_are_incremental_and_idempotent(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    first = apply_memory_spike_round(db_path, "round_01_recon")
    second = apply_memory_spike_round(db_path, "round_02_exploit")
    repeated = apply_memory_spike_round(db_path, "round_02_exploit")

    conn = connect_db(db_path)
    case = conn.execute(
        "select overall_severity, current_stage from cases where case_id = ?",
        ("case_demo_001",),
    ).fetchone()

    assert first["applied"] is True
    assert second["applied"] is True
    assert repeated["applied"] is False
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 8
    assert case["overall_severity"] == "high"
    assert case["current_stage"] == "persistence"


def test_apply_memory_spike_round_requires_previous_round(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"
    bootstrap_memory_spike_database(db_path)

    with pytest.raises(ValueError, match="previous round must be applied first"):
        apply_memory_spike_round(db_path, "round_03_new_ip")


def test_memory_spike_module_supports_bootstrap_and_apply_round(tmp_path) -> None:
    db_path = tmp_path / "memory-spike.db"

    bootstrap = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_analyst_agent.memory_spike",
            "bootstrap",
            "--db-path",
            str(db_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bootstrap.returncode == 0
    assert "bootstrapped memory spike" in bootstrap.stdout

    apply_round = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_analyst_agent.memory_spike",
            "apply-round",
            "--db-path",
            str(db_path),
            "--round-id",
            "round_01_recon",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert apply_round.returncode == 0
    body = json.loads(apply_round.stdout)
    assert body["round_id"] == "round_01_recon"
    assert body["applied"] is True
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_memory_spike.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'security_analyst_agent.memory_spike'` and/or `sqlite3.OperationalError: no such table: spike_round_runs`

- [ ] **Step 3: 先在 `db.py` 里声明轮次状态表**

```python
create table if not exists spike_round_runs (
  round_id text primary key,
  applied_at text not null
);
```

- [ ] **Step 4: 创建最小 `memory_spike.py` 模块骨架**

```python
from __future__ import annotations

from pathlib import Path


def load_memory_spike_rounds() -> list[dict]:
    return []


def bootstrap_memory_spike_database(db_path: Path) -> None:
    raise NotImplementedError


def apply_memory_spike_round(db_path: Path, round_id: str) -> dict:
    raise NotImplementedError
```

- [ ] **Step 5: 再跑一次失败测试，确认失败点已经集中在未实现逻辑**

Run: `uv run pytest tests/test_memory_spike.py -q`
Expected: FAIL with `NotImplementedError`, assertion mismatch, or missing fixture file errors

### Task 2: 实现基础种子、6 轮增量批次和增量导入模块

**Files:**
- Create: `fixtures/spike_memory/base_bundle.json`
- Create: `fixtures/spike_memory/rounds.json`
- Create: `src/security_analyst_agent/memory_spike.py`
- Modify: `src/security_analyst_agent/config.py`
- Modify: `src/security_analyst_agent/db.py`
- Test: `tests/test_memory_spike.py`

- [ ] **Step 1: 在 `config.py` 中增加 Memory Spike 路径常量**

```python
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent
FIXTURE_DIR = PROJECT_ROOT / "fixtures" / "spike"
SPIKE_MEMORY_DIR = PROJECT_ROOT / "fixtures" / "spike_memory"
DEFAULT_DB_PATH = PROJECT_ROOT / "spike.db"
DEFAULT_MEMORY_SPIKE_DB_PATH = PROJECT_ROOT / "memory-spike.db"
```

- [ ] **Step 2: 在 `db.py` 中补齐 `spike_round_runs` 表**

```python
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
        create table if not exists spike_round_runs (
          round_id text primary key,
          applied_at text not null
        );
        """
    )
```

- [ ] **Step 3: 创建基础种子文件 `fixtures/spike_memory/base_bundle.json`**

```json
{
  "assets": [
    {
      "asset_id": "asset_api_prod",
      "asset_name": "api-prod",
      "system_name": "统一认证 API",
      "owner_team": "identity",
      "internet_exposed": 1,
      "public_ip": "203.0.113.10",
      "domain": "api.example.com"
    },
    {
      "asset_id": "asset_admin_portal",
      "asset_name": "admin-portal",
      "system_name": "运营管理后台",
      "owner_team": "ops",
      "internet_exposed": 1,
      "public_ip": "203.0.113.11",
      "domain": "admin.example.com"
    },
    {
      "asset_id": "asset_static_www",
      "asset_name": "www-static",
      "system_name": "官网静态站点",
      "owner_team": "web",
      "internet_exposed": 1,
      "public_ip": "203.0.113.12",
      "domain": "www.example.com"
    }
  ],
  "cases": [],
  "alerts": [],
  "timeline_events": [],
  "evidence": [],
  "intel_cache": [
    {
      "indicator": "198.51.100.23",
      "indicator_type": "ip",
      "verdict": "malicious",
      "confidence": 0.92,
      "queried_at": "2026-04-12T12:00:00+08:00"
    },
    {
      "indicator": "198.51.100.200",
      "indicator_type": "ip",
      "verdict": "benign",
      "confidence": 0.85,
      "queried_at": "2026-04-12T12:30:00+08:00"
    }
  ]
}
```

- [ ] **Step 4: 创建 `fixtures/spike_memory/rounds.json`，一次性写入 6 轮批次**

```json
[
  {
    "round_id": "round_01_recon",
    "previous_round_id": null,
    "cases_upsert": [
      {
        "case_id": "case_demo_001",
        "title": "多阶段 Web 入侵与后续横向准备",
        "status": "open",
        "overall_severity": "medium",
        "current_stage": "recon",
        "primary_actor_id": "actor_demo_001"
      },
      {
        "case_id": "case_noise_001",
        "title": "低质量扫描与误报混合事件",
        "status": "observing",
        "overall_severity": "low",
        "current_stage": "recon",
        "primary_actor_id": "actor_noise_001"
      }
    ],
    "alerts": [
      {
        "alert_id": "alt_r1_api_scan",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-10T09:10:00+08:00",
        "title": "扫描统一认证 API 登录入口",
        "status": "open",
        "severity": "medium",
        "attack_stage": "recon",
        "src_ip": "198.51.100.23",
        "dst_ip": "203.0.113.10",
        "asset_id": "asset_api_prod"
      },
      {
        "alert_id": "alt_r1_admin_scan",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-10T09:11:00+08:00",
        "title": "扫描运营后台登录入口",
        "status": "open",
        "severity": "medium",
        "attack_stage": "recon",
        "src_ip": "198.51.100.23",
        "dst_ip": "203.0.113.11",
        "asset_id": "asset_admin_portal"
      },
      {
        "alert_id": "alt_r1_static_scan",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-10T09:12:00+08:00",
        "title": "扫描官网静态站点历史路径",
        "status": "open",
        "severity": "medium",
        "attack_stage": "recon",
        "src_ip": "198.51.100.23",
        "dst_ip": "203.0.113.12",
        "asset_id": "asset_static_www"
      },
      {
        "alert_id": "alt_r1_noise_probe",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-10T09:14:00+08:00",
        "title": "低价值目录探测命中通用规则",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "203.0.113.200",
        "dst_ip": "203.0.113.12",
        "asset_id": "asset_static_www"
      }
    ],
    "timeline_events": [
      {
        "timeline_event_id": "tl_r1_recon_main",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-10T09:10:00+08:00",
        "stage": "recon",
        "title": "同一来源对三个公网入口进行打点",
        "related_alert_ids": ["alt_r1_api_scan", "alt_r1_admin_scan", "alt_r1_static_scan"],
        "related_evidence_ids": []
      },
      {
        "timeline_event_id": "tl_r1_noise_minor",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-10T09:14:00+08:00",
        "stage": "recon",
        "title": "低价值目录探测触发通用规则",
        "related_alert_ids": ["alt_r1_noise_probe"],
        "related_evidence_ids": []
      }
    ],
    "evidence": [],
    "intel_cache_upsert": []
  },
  {
    "round_id": "round_02_exploit",
    "previous_round_id": "round_01_recon",
    "cases_upsert": [
      {
        "case_id": "case_demo_001",
        "title": "多阶段 Web 入侵与后续横向准备",
        "status": "open",
        "overall_severity": "high",
        "current_stage": "persistence",
        "primary_actor_id": "actor_demo_001"
      },
      {
        "case_id": "case_noise_001",
        "title": "低质量扫描与误报混合事件",
        "status": "observing",
        "overall_severity": "low",
        "current_stage": "recon",
        "primary_actor_id": "actor_noise_001"
      }
    ],
    "alerts": [
      {
        "alert_id": "alt_r2_webshell",
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
        "alert_id": "alt_r2_noise_repeat",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-11T14:05:00+08:00",
        "title": "重复目录探测命中旧规则",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "203.0.113.200",
        "dst_ip": "203.0.113.12",
        "asset_id": "asset_static_www"
      },
      {
        "alert_id": "alt_r2_noise_healthcheck",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-11T14:06:00+08:00",
        "title": "健康检查流量误命中高误报规则",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "198.51.100.200",
        "dst_ip": "203.0.113.11",
        "asset_id": "asset_admin_portal"
      },
      {
        "alert_id": "alt_r2_noise_proxy_probe",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-11T14:08:00+08:00",
        "title": "代理出口随机目录探测",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "192.0.2.56",
        "dst_ip": "203.0.113.11",
        "asset_id": "asset_admin_portal"
      }
    ],
    "timeline_events": [
      {
        "timeline_event_id": "tl_r2_webshell",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-11T14:20:00+08:00",
        "stage": "persistence",
        "title": "利用漏洞写入 webshell",
        "related_alert_ids": ["alt_r2_webshell"],
        "related_evidence_ids": ["evi_webshell_01"]
      }
    ],
    "evidence": [
      {
        "evidence_id": "evi_webshell_01",
        "case_id": "case_demo_001",
        "evidence_type": "payload",
        "summary": "上传行为包含 webshell 落地痕迹"
      }
    ],
    "intel_cache_upsert": []
  },
  {
    "round_id": "round_03_new_ip",
    "previous_round_id": "round_02_exploit",
    "cases_upsert": [
      {
        "case_id": "case_demo_001",
        "title": "多阶段 Web 入侵与后续横向准备",
        "status": "open",
        "overall_severity": "high",
        "current_stage": "command_execution",
        "primary_actor_id": "actor_demo_001"
      }
    ],
    "alerts": [
      {
        "alert_id": "alt_r3_shell_new_ip",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-12T11:03:00+08:00",
        "title": "新 IP 连接既有 webshell",
        "status": "open",
        "severity": "high",
        "attack_stage": "command_execution",
        "src_ip": "198.51.100.77",
        "dst_ip": "203.0.113.10",
        "asset_id": "asset_api_prod"
      },
      {
        "alert_id": "alt_r3_noise_proxy_shift",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-12T11:05:00+08:00",
        "title": "代理出口变化导致目录探测源地址波动",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "192.0.2.91",
        "dst_ip": "203.0.113.12",
        "asset_id": "asset_static_www"
      }
    ],
    "timeline_events": [
      {
        "timeline_event_id": "tl_r3_new_ip",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-12T11:03:00+08:00",
        "stage": "command_execution",
        "title": "新源 IP 连接既有 webshell 并尝试命令执行",
        "related_alert_ids": ["alt_r3_shell_new_ip"],
        "related_evidence_ids": ["evi_shell_conn_01"]
      }
    ],
    "evidence": [
      {
        "evidence_id": "evi_shell_conn_01",
        "case_id": "case_demo_001",
        "evidence_type": "connection",
        "summary": "新源 IP 连接已存在 webshell"
      }
    ],
    "intel_cache_upsert": [
      {
        "indicator": "198.51.100.77",
        "indicator_type": "ip",
        "verdict": "unknown",
        "confidence": 0.0,
        "queried_at": "2026-04-12T11:10:00+08:00"
      }
    ]
  },
  {
    "round_id": "round_04_lateral_prep",
    "previous_round_id": "round_03_new_ip",
    "cases_upsert": [
      {
        "case_id": "case_demo_001",
        "title": "多阶段 Web 入侵与后续横向准备",
        "status": "open",
        "overall_severity": "high",
        "current_stage": "lateral_prep",
        "primary_actor_id": "actor_demo_001"
      }
    ],
    "alerts": [
      {
        "alert_id": "alt_r4_internal_scan",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-12T11:20:00+08:00",
        "title": "webshell 后触发内网扫描准备",
        "status": "open",
        "severity": "high",
        "attack_stage": "lateral_prep",
        "src_ip": "198.51.100.77",
        "dst_ip": "10.0.0.12",
        "asset_id": "asset_api_prod"
      },
      {
        "alert_id": "alt_r4_host_noise",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-12T11:22:00+08:00",
        "title": "主机侧低价值进程异常",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": null,
        "dst_ip": "203.0.113.11",
        "asset_id": "asset_admin_portal"
      }
    ],
    "timeline_events": [
      {
        "timeline_event_id": "tl_r4_lateral_prep",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-12T11:20:00+08:00",
        "stage": "lateral_prep",
        "title": "命令执行后出现横向准备迹象",
        "related_alert_ids": ["alt_r4_internal_scan"],
        "related_evidence_ids": ["evi_lateral_01"]
      }
    ],
    "evidence": [
      {
        "evidence_id": "evi_lateral_01",
        "case_id": "case_demo_001",
        "evidence_type": "host_activity",
        "summary": "受害主机出现横向探测特征"
      }
    ],
    "intel_cache_upsert": []
  },
  {
    "round_id": "round_05_silent_period",
    "previous_round_id": "round_04_lateral_prep",
    "cases_upsert": [
      {
        "case_id": "case_demo_001",
        "title": "多阶段 Web 入侵与后续横向准备",
        "status": "open",
        "overall_severity": "high",
        "current_stage": "lateral_prep",
        "primary_actor_id": "actor_demo_001"
      }
    ],
    "alerts": [
      {
        "alert_id": "alt_r5_noise_repeat",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-13T10:00:00+08:00",
        "title": "低质量扫描器重复命中通用规则",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "203.0.113.201",
        "dst_ip": "203.0.113.12",
        "asset_id": "asset_static_www"
      }
    ],
    "timeline_events": [],
    "evidence": [],
    "intel_cache_upsert": []
  },
  {
    "round_id": "round_06_reactivation",
    "previous_round_id": "round_05_silent_period",
    "cases_upsert": [
      {
        "case_id": "case_demo_001",
        "title": "多阶段 Web 入侵与后续横向准备",
        "status": "open",
        "overall_severity": "high",
        "current_stage": "lateral_prep",
        "primary_actor_id": "actor_demo_001"
      }
    ],
    "alerts": [
      {
        "alert_id": "alt_r6_shell_reactivation",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-14T08:30:00+08:00",
        "title": "静默后再次连接既有 webshell",
        "status": "open",
        "severity": "high",
        "attack_stage": "command_execution",
        "src_ip": "198.51.100.91",
        "dst_ip": "203.0.113.10",
        "asset_id": "asset_api_prod"
      },
      {
        "alert_id": "alt_r6_noise_api_probe",
        "case_id": "case_noise_001",
        "occurred_at": "2026-04-14T08:32:00+08:00",
        "title": "无状态 API 探测命中旧规则",
        "status": "open",
        "severity": "low",
        "attack_stage": "recon",
        "src_ip": "192.0.2.123",
        "dst_ip": "203.0.113.11",
        "asset_id": "asset_admin_portal"
      }
    ],
    "timeline_events": [
      {
        "timeline_event_id": "tl_r6_reactivation",
        "case_id": "case_demo_001",
        "occurred_at": "2026-04-14T08:30:00+08:00",
        "stage": "command_execution",
        "title": "静默期后再次出现对既有落点的访问",
        "related_alert_ids": ["alt_r6_shell_reactivation"],
        "related_evidence_ids": ["evi_reactivation_01"]
      }
    ],
    "evidence": [
      {
        "evidence_id": "evi_reactivation_01",
        "case_id": "case_demo_001",
        "evidence_type": "connection",
        "summary": "静默后再次出现对既有落点的访问"
      }
    ],
    "intel_cache_upsert": [
      {
        "indicator": "198.51.100.91",
        "indicator_type": "ip",
        "verdict": "unknown",
        "confidence": 0.0,
        "queried_at": "2026-04-14T08:35:00+08:00"
      }
    ]
  }
]
```

- [ ] **Step 5: 实现 `src/security_analyst_agent/memory_spike.py`**

```python
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from security_analyst_agent.config import DEFAULT_MEMORY_SPIKE_DB_PATH, SPIKE_MEMORY_DIR
from security_analyst_agent.db import connect_db, create_schema


RESET_TABLES = (
    "spike_round_runs",
    "intel_cache",
    "evidence",
    "timeline_events",
    "alerts",
    "cases",
    "assets",
)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _reset_tables(conn: sqlite3.Connection) -> None:
    for table_name in RESET_TABLES:
        conn.execute(f"delete from {table_name}")


def _insert_many(conn: sqlite3.Connection, table_name: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    columns = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in columns)
    sql = f"insert into {table_name} ({', '.join(columns)}) values ({placeholders})"
    values = [tuple(row[column] for column in columns) for row in rows]
    conn.executemany(sql, values)


def _upsert_many(
    conn: sqlite3.Connection,
    table_name: str,
    rows: list[dict[str, Any]],
    key_columns: list[str],
) -> None:
    if not rows:
        return
    columns = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in columns)
    update_columns = [column for column in columns if column not in key_columns]
    update_clause = ", ".join(f"{column}=excluded.{column}" for column in update_columns)
    sql = (
        f"insert into {table_name} ({', '.join(columns)}) values ({placeholders}) "
        f"on conflict({', '.join(key_columns)}) do update set {update_clause}"
    )
    values = [tuple(row[column] for column in columns) for row in rows]
    conn.executemany(sql, values)


def _prepare_timeline_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for row in rows:
        prepared_row = dict(row)
        prepared_row["related_alert_ids"] = json.dumps(row["related_alert_ids"], ensure_ascii=False)
        prepared_row["related_evidence_ids"] = json.dumps(row["related_evidence_ids"], ensure_ascii=False)
        prepared.append(prepared_row)
    return prepared


def load_memory_spike_rounds(fixture_dir: Path = SPIKE_MEMORY_DIR) -> list[dict[str, Any]]:
    rounds = _read_json(fixture_dir / "rounds.json")
    assert isinstance(rounds, list)
    return rounds


def bootstrap_memory_spike_database(db_path: Path, fixture_dir: Path = SPIKE_MEMORY_DIR) -> None:
    conn = connect_db(db_path)
    create_schema(conn)
    bundle = _read_json(fixture_dir / "base_bundle.json")
    _reset_tables(conn)
    _insert_many(conn, "assets", bundle["assets"])
    _insert_many(conn, "cases", bundle["cases"])
    _insert_many(conn, "alerts", bundle["alerts"])
    _insert_many(conn, "timeline_events", _prepare_timeline_rows(bundle["timeline_events"]))
    _insert_many(conn, "evidence", bundle["evidence"])
    _insert_many(conn, "intel_cache", bundle["intel_cache"])
    conn.commit()
    conn.close()


def _load_round_map(fixture_dir: Path) -> dict[str, dict[str, Any]]:
    return {item["round_id"]: item for item in load_memory_spike_rounds(fixture_dir)}


def _round_is_applied(conn: sqlite3.Connection, round_id: str) -> bool:
    row = conn.execute("select 1 from spike_round_runs where round_id = ?", (round_id,)).fetchone()
    return row is not None


def apply_memory_spike_round(
    db_path: Path,
    round_id: str,
    fixture_dir: Path = SPIKE_MEMORY_DIR,
) -> dict[str, Any]:
    round_map = _load_round_map(fixture_dir)
    if round_id not in round_map:
        raise ValueError(f"unknown round_id: {round_id}")

    conn = connect_db(db_path)
    create_schema(conn)
    batch = round_map[round_id]

    if _round_is_applied(conn, round_id):
        return {"round_id": round_id, "applied": False, "reason": "already_applied"}

    previous_round_id = batch["previous_round_id"]
    if previous_round_id and not _round_is_applied(conn, previous_round_id):
        raise ValueError("previous round must be applied first")

    _upsert_many(conn, "cases", batch["cases_upsert"], ["case_id"])
    _insert_many(conn, "alerts", batch["alerts"])
    _insert_many(conn, "timeline_events", _prepare_timeline_rows(batch["timeline_events"]))
    _insert_many(conn, "evidence", batch["evidence"])
    _upsert_many(conn, "intel_cache", batch["intel_cache_upsert"], ["indicator", "indicator_type"])
    conn.execute(
        "insert into spike_round_runs (round_id, applied_at) values (?, ?)",
        (round_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    return {
        "round_id": round_id,
        "applied": True,
        "inserted_alerts": len(batch["alerts"]),
        "upserted_cases": len(batch["cases_upsert"]),
        "inserted_timeline_events": len(batch["timeline_events"]),
        "inserted_evidence": len(batch["evidence"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory spike bootstrap/apply-round helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap_parser = subparsers.add_parser("bootstrap")
    bootstrap_parser.add_argument("--db-path", type=Path, default=DEFAULT_MEMORY_SPIKE_DB_PATH)

    apply_parser = subparsers.add_parser("apply-round")
    apply_parser.add_argument("--db-path", type=Path, default=DEFAULT_MEMORY_SPIKE_DB_PATH)
    apply_parser.add_argument("--round-id", required=True)

    args = parser.parse_args()
    if args.command == "bootstrap":
        bootstrap_memory_spike_database(args.db_path)
        print(f"bootstrapped memory spike: {args.db_path}")
        return

    body = apply_memory_spike_round(args.db_path, args.round_id)
    print(json.dumps(body, ensure_ascii=False))


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: 跑测试确认 round fixture 与增量导入都通过**

Run: `uv run pytest tests/test_memory_spike.py -q`
Expected: PASS

- [ ] **Step 7: 提交这一批实现**

```bash
git add fixtures/spike_memory/base_bundle.json \
  fixtures/spike_memory/rounds.json \
  src/security_analyst_agent/config.py \
  src/security_analyst_agent/db.py \
  src/security_analyst_agent/memory_spike.py \
  tests/test_memory_spike.py
git commit -m "feat: add hermes memory spike fixtures"
```

### Task 3: 编写多轮 Hermes 巡检 runbook，并把验收点固化进测试

**Files:**
- Create: `docs/runbooks/hermes-memory-spike.md`
- Modify: `tests/test_hermes_artifacts.py`
- Test: `tests/test_hermes_artifacts.py`

- [ ] **Step 1: 先补 runbook 约束测试**

```python
def test_memory_spike_runbook_contains_round_commands() -> None:
    text = Path("docs/runbooks/hermes-memory-spike.md").read_text(encoding="utf-8")

    assert "security_analyst_agent.memory_spike bootstrap" in text
    assert "round_01_recon" in text
    assert "round_06_reactivation" in text
    assert "Memory Summary" in text
    assert "次要干扰案件" in text
    assert "主案件" in text
    assert "不要把 Hermes memory 当事实源" in text
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `uv run pytest tests/test_hermes_artifacts.py::test_memory_spike_runbook_contains_round_commands -q`
Expected: FAIL with `FileNotFoundError: docs/runbooks/hermes-memory-spike.md`

- [ ] **Step 3: 编写 `docs/runbooks/hermes-memory-spike.md`**

```md
# Hermes Memory Spike Runbook

## Scope

- 只用于验证 `Hermes` 的长期记忆价值
- 不用于真实设备接入
- 数据库仍是事实源，`Hermes memory` 只看作工作记忆

## Prerequisites

1. 已完成 `docs/runbooks/hermes-runtime-bootstrap.md`
2. 已确认 `secagent-patrol` 已绑定到巡检任务
3. 已安装项目依赖：`uv sync --extra dev`

## Bootstrap

```bash
uv run python -m security_analyst_agent.memory_spike bootstrap --db-path ./memory-spike.db
```

## Round Loop

### Round 1

```bash
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_01_recon
hermes cron run d27a82c0fa79
hermes cron tick
```

检查：

- 主案件是否已出现
- 是否提到需要继续关注的资产或来源
- `Memory Summary` 是否写出下一轮关注点

### Round 2

```bash
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_02_exploit
hermes cron run d27a82c0fa79
hermes cron tick
```

检查：

- 是否将利用成功与上一轮侦察串联
- 是否仍保留次要干扰案件但不给过高优先级

### Round 3

```bash
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_03_new_ip
hermes cron run d27a82c0fa79
hermes cron tick
```

检查：

- 是否因为新 IP 保持谨慎而不是直接拆案
- 是否将新 IP 与既有 webshell 关联起来

### Round 4

```bash
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_04_lateral_prep
hermes cron run d27a82c0fa79
hermes cron tick
```

检查：

- 是否将案件阶段推进到 `lateral_prep`
- 是否清楚区分主证据和未证实部分

### Round 5

```bash
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_05_silent_period
hermes cron run d27a82c0fa79
hermes cron tick
```

检查：

- 是否保持主案件 watchlist
- 是否不会因为静默期直接“洗白”案件

### Round 6

```bash
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_06_reactivation
hermes cron run d27a82c0fa79
hermes cron tick
```

检查：

- 是否快速承接旧案件上下文
- `Memory Summary` 是否保留主案件和次要干扰案件的优先级

## Acceptance Checklist

- 主案件能跨轮连续维护
- 次要干扰案件不会抢占主案件优先级
- `Memory Summary` 每轮都可复用
- 不要把 Hermes memory 当事实源
- 事实结论必须能回溯到数据库和 Tool 输出
```

- [ ] **Step 4: 在 `tests/test_hermes_artifacts.py` 中追加新断言**

```python
def test_memory_spike_runbook_contains_round_commands() -> None:
    text = Path("docs/runbooks/hermes-memory-spike.md").read_text(encoding="utf-8")

    assert "security_analyst_agent.memory_spike bootstrap" in text
    assert "round_01_recon" in text
    assert "round_06_reactivation" in text
    assert "Memory Summary" in text
    assert "次要干扰案件" in text
    assert "主案件" in text
    assert "不要把 Hermes memory 当事实源" in text
```

- [ ] **Step 5: 跑文档与产物测试**

Run: `uv run pytest tests/test_hermes_artifacts.py -q`
Expected: PASS

- [ ] **Step 6: 提交这一批实现**

```bash
git add docs/runbooks/hermes-memory-spike.md tests/test_hermes_artifacts.py
git commit -m "docs: add hermes memory spike runbook"
```

### Task 4: 做一次完整回归并保留人工验收入口

**Files:**
- Modify: `docs/runbooks/hermes-memory-spike.md`
- Test: `tests/test_memory_spike.py`
- Test: `tests/test_hermes_artifacts.py`
- Test: `tests/test_cli_e2e.py`

- [ ] **Step 1: 先跑 Python 侧完整回归**

Run: `uv run pytest tests/test_memory_spike.py tests/test_hermes_artifacts.py tests/test_cli_e2e.py -q`
Expected: PASS

- [ ] **Step 2: 跑一次 Memory Spike 命令链的本地冒烟**

Run:

```bash
uv run python -m security_analyst_agent.memory_spike bootstrap --db-path ./memory-spike.db
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_01_recon
uv run python -m security_analyst_agent.memory_spike apply-round --db-path ./memory-spike.db --round-id round_02_exploit
```

Expected:

- 第一个命令输出 `bootstrapped memory spike:`
- 第二个命令返回 `{"round_id": "round_01_recon", "applied": true, ...}`
- 第三个命令返回 `{"round_id": "round_02_exploit", "applied": true, ...}`

- [ ] **Step 3: 如果命令输出与测试一致，再执行一次全量回归**

Run: `uv run pytest -q`
Expected: PASS

- [ ] **Step 4: 如有必要，补一行 runbook 说明默认数据库文件名**

```md
默认演练数据库路径采用 `./memory-spike.db`，避免覆盖现有 `./spike.db`。
```

- [ ] **Step 5: 提交最终收尾**

```bash
git add docs/runbooks/hermes-memory-spike.md
git commit -m "test: verify hermes memory spike harness"
```

## Self-Review

### Spec Coverage

- 多轮增量告警：由 `fixtures/spike_memory/rounds.json` 和 `memory_spike.py` 覆盖
- 噪音和次要干扰案件：由 `rounds.json` 覆盖
- 不扩大 Tool 面：整个计划没有修改 `tool_dispatch.py`、`cli.py` 或 `mcp_server.py`
- 验证 `Memory Summary` 价值：由 `docs/runbooks/hermes-memory-spike.md` 的 round checklist 覆盖
- `Hermes` 只是记忆层、数据库仍是事实源：由 `runbook` 与 `tests/test_hermes_artifacts.py` 断言覆盖

### Placeholder Scan

- 计划中没有占位词或“留到以后再补”的描述
- 所有新增文件都有精确路径
- 每个任务都包含具体命令和预期输出

### Type Consistency

- 轮次文件统一使用 `round_id` / `previous_round_id`
- 时间线字段统一使用 `timeline_events`
- 情报字段统一使用 `intel_cache_upsert`
- 导入返回统一使用 `applied` 布尔值与 `round_id`

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-14-hermes-memory-spike.md`. Two execution options:

1. Subagent-Driven (recommended) - I dispatch a fresh subagent per task, review between tasks, fast iteration
2. Inline Execution - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
