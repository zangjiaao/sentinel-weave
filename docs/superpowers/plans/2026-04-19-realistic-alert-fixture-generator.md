# Realistic Alert Fixture Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增可复现的“真实风格”告警样本生成能力，产出 `5轮x1000`、2条攻击链混入噪音的数据集，并兼容 `attack_stage` 缺失场景（落 `unknown` + 保存 `raw_attack_stage`）。

**Architecture:** 采用模板驱动生成器：攻击链模板与噪音模板统一汇总到一条生成流水线，按轮次配比与时间窗口混排，最终输出 `fixtures/spike_memory_realistic/rounds.json`。底层 schema 扩展 `alerts.raw_attack_stage`，保持 `attack_stage NOT NULL` 不变，避免影响现有 scoring/聚类逻辑。

**Tech Stack:** Python 3.11, SQLite, pytest, 现有 `memory_spike`/`openai_slow_verify` 流程。

---

## File Structure (locked before tasks)

- Create: `src/security_analyst_agent/tools/generate_alert_fixture.py`
  - 负责模板定义、随机生成、round 输出写盘（可复现 seed）
- Create: `tests/test_generate_alert_fixture.py`
  - 负责生成器结构、分布、去诱导性、缺失 stage 规则测试
- Create: `fixtures/spike_memory_realistic/base_bundle.json`
  - 真实样本的基础资产/缓存数据
- Create: `docs/runbooks/manifests/hermes-slow-integration-realistic.json`
  - realistic slow verify 入口
- Modify: `src/security_analyst_agent/db.py`
  - `alerts` 增加 `raw_attack_stage`，并补 shape migration
- Modify: `src/security_analyst_agent/ingest.py`
  - upsert 时支持 `raw_attack_stage`
- Modify: `src/security_analyst_agent/memory_spike.py`
  - 兼容加载包含 `raw_attack_stage` 的 alerts rows
- Modify: `tests/test_bootstrap.py`
  - 验证 schema/migration 对 `raw_attack_stage` 的兼容
- Modify: `tests/test_memory_spike.py`
  - 验证 realistic fixture 可以 bootstrap + apply

---

### Task 1: 扩展 alerts schema 与导入路径

**Files:**
- Modify: `src/security_analyst_agent/db.py`
- Modify: `src/security_analyst_agent/ingest.py`
- Test: `tests/test_bootstrap.py`

- [ ] **Step 1: 写失败测试（alerts 包含 raw_attack_stage）**

```python
def test_create_schema_adds_raw_attack_stage_column_for_alerts(tmp_path) -> None:
    db_path = tmp_path / "schema.db"
    conn = connect_db(db_path)
    create_schema(conn)

    columns = {row["name"] for row in conn.execute("pragma table_info(alerts)").fetchall()}
    assert "raw_attack_stage" in columns
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_bootstrap.py::test_create_schema_adds_raw_attack_stage_column_for_alerts -v`
Expected: `FAIL`（列不存在）

- [ ] **Step 3: 最小实现 schema + migration + ingest**

```python
# db.py

def _ensure_alerts_shape(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("pragma table_info(alerts)").fetchall()}
    if not columns:
        return
    if "raw_attack_stage" not in columns:
        conn.execute("alter table alerts add column raw_attack_stage text")

# create_schema alerts 表定义新增：
# raw_attack_stage text,

# create_schema() 末尾调用 _ensure_alerts_shape(conn)

# ingest.py _upsert_alerts columns 增加 raw_attack_stage
columns = [
    "alert_id", "occurred_at", "title", "status", "severity",
    "attack_stage", "raw_attack_stage", "src_ip", "dst_ip", "asset_id",
]
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_bootstrap.py::test_create_schema_adds_raw_attack_stage_column_for_alerts -v`
Expected: `PASS`

- [ ] **Step 5: 提交**

```bash
git add src/security_analyst_agent/db.py src/security_analyst_agent/ingest.py tests/test_bootstrap.py
git commit -m "feat(schema): add alerts.raw_attack_stage with backward-compatible migration"
```

---

### Task 2: 生成器骨架与 deterministic 输出

**Files:**
- Create: `src/security_analyst_agent/tools/generate_alert_fixture.py`
- Test: `tests/test_generate_alert_fixture.py`

- [ ] **Step 1: 写失败测试（固定 seed 输出稳定）**

```python
from security_analyst_agent.tools.generate_alert_fixture import generate_rounds


def test_generate_rounds_is_deterministic_with_same_seed() -> None:
    rounds_a = generate_rounds(round_count=5, alerts_per_round=1000, chain_count=2, seed=20260419)
    rounds_b = generate_rounds(round_count=5, alerts_per_round=1000, chain_count=2, seed=20260419)
    assert rounds_a == rounds_b
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_generate_alert_fixture.py::test_generate_rounds_is_deterministic_with_same_seed -v`
Expected: `FAIL`（模块或函数不存在）

- [ ] **Step 3: 实现生成器最小骨架**

```python
# generate_alert_fixture.py

def generate_rounds(*, round_count: int, alerts_per_round: int, chain_count: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rounds: list[dict[str, Any]] = []
    previous_round_id: str | None = None
    for index in range(1, round_count + 1):
        round_id = f"round_{index:02d}_realistic"
        rounds.append(
            {
                "round_id": round_id,
                "previous_round_id": previous_round_id,
                "cases_upsert": [],
                "alerts": [],
                "timeline_events": [],
                "evidence": [],
                "intel_cache_upsert": [],
            }
        )
        previous_round_id = round_id
    return rounds
```

- [ ] **Step 4: 运行测试确认通过（仅 deterministic 骨架）**

Run: `pytest tests/test_generate_alert_fixture.py::test_generate_rounds_is_deterministic_with_same_seed -v`
Expected: `PASS`

- [ ] **Step 5: 提交**

```bash
git add src/security_analyst_agent/tools/generate_alert_fixture.py tests/test_generate_alert_fixture.py
git commit -m "feat(fixtures): scaffold deterministic realistic alert generator"
```

---

### Task 3: 实现模板驱动生成（5x1000，2条链）

**Files:**
- Modify: `src/security_analyst_agent/tools/generate_alert_fixture.py`
- Test: `tests/test_generate_alert_fixture.py`

- [ ] **Step 1: 写失败测试（规模、配比、去诱导、stage 缺失规则）**

```python
import re
from security_analyst_agent.tools.generate_alert_fixture import generate_rounds


def test_generate_rounds_shape_distribution_and_stage_fallback() -> None:
    rounds = generate_rounds(round_count=5, alerts_per_round=1000, chain_count=2, seed=7)
    assert len(rounds) == 5
    assert all(len(item["alerts"]) == 1000 for item in rounds)

    all_alerts = [alert for item in rounds for alert in item["alerts"]]
    assert len(all_alerts) == 5000

    attack_signal = [a for a in all_alerts if a["severity"] in {"high", "critical"}]
    assert len(attack_signal) >= 80

    assert all(a.get("attack_stage") for a in all_alerts)
    for a in all_alerts:
        if not a.get("raw_attack_stage"):
            assert a["attack_stage"] in {"unknown", "recon", "exploit", "persistence", "command_execution", "lateral_prep", "reactivation"}

    bad_ids = [a["alert_id"] for a in all_alerts if re.search(r"(chain|round|r\d+)", a["alert_id"], re.I)]
    assert bad_ids == []
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_generate_alert_fixture.py::test_generate_rounds_shape_distribution_and_stage_fallback -v`
Expected: `FAIL`

- [ ] **Step 3: 实现模板驱动与混入策略**

```python
# 关键结构示意（完整实现写入文件）
ATTACK_STAGE_VALUES = {"recon", "exploit", "persistence", "command_execution", "lateral_prep", "reactivation"}

@dataclass(frozen=True)
class AttackTemplate:
    chain: str
    stage_by_round: dict[int, str]
    assets: tuple[str, ...]
    src_ip_pool: tuple[str, ...]
    severity_by_stage: dict[str, str]


def _normalize_stage(raw_stage: str | None) -> tuple[str, str | None]:
    if not raw_stage:
        return "unknown", None
    normalized = str(raw_stage).strip().lower()
    if normalized in ATTACK_STAGE_VALUES:
        return normalized, raw_stage
    return "unknown", raw_stage


def _build_alert_id(rng: random.Random, index: int) -> str:
    return f"alt_{rng.getrandbits(48):012x}_{index:04d}"


def _build_noise_alert(...):
    # 低/中危，raw_attack_stage 部分为空
    ...


def _build_attack_alert(...):
    # 高价值模板，stage 可追溯推进
    ...


def generate_rounds(...):
    # 每轮先生成噪音，再插入攻击链告警并按 occurred_at 打散排序
    ...
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_generate_alert_fixture.py -v`
Expected: `PASS`

- [ ] **Step 5: 提交**

```bash
git add src/security_analyst_agent/tools/generate_alert_fixture.py tests/test_generate_alert_fixture.py
git commit -m "feat(fixtures): implement template-driven realistic alert generation"
```

---

### Task 4: 写盘入口、fixture 目录与 realistic manifest

**Files:**
- Create: `fixtures/spike_memory_realistic/base_bundle.json`
- Create: `docs/runbooks/manifests/hermes-slow-integration-realistic.json`
- Modify: `src/security_analyst_agent/tools/generate_alert_fixture.py`
- Test: `tests/test_memory_spike.py`

- [ ] **Step 1: 写失败测试（realistic fixture 可被 memory_spike 加载）**

```python
from security_analyst_agent.config import PROJECT_ROOT
from security_analyst_agent.memory_spike import load_memory_spike_rounds


def test_load_realistic_memory_spike_rounds_returns_five_rounds() -> None:
    rounds = load_memory_spike_rounds(PROJECT_ROOT / "fixtures" / "spike_memory_realistic")
    assert len(rounds) == 5
    assert rounds[0]["round_id"] == "round_01_realistic"
    assert len(rounds[0]["alerts"]) == 1000
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_memory_spike.py::test_load_realistic_memory_spike_rounds_returns_five_rounds -v`
Expected: `FAIL`（目录或文件不存在）

- [ ] **Step 3: 实现 CLI 写盘 + fixture 文件**

```python
# generate_alert_fixture.py main()
# 参数：--output-dir --rounds --per-round --chains --seed
# 输出：<output-dir>/rounds.json

# base_bundle.json 复制 expanded 资产池并精简 intel_cache
# manifest 新增 scenario=hermes-slow-integration-realistic，rounds=round_01..05
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_memory_spike.py::test_load_realistic_memory_spike_rounds_returns_five_rounds -v`
Expected: `PASS`

- [ ] **Step 5: 提交**

```bash
git add src/security_analyst_agent/tools/generate_alert_fixture.py fixtures/spike_memory_realistic/base_bundle.json docs/runbooks/manifests/hermes-slow-integration-realistic.json tests/test_memory_spike.py
git commit -m "feat(fixtures): add realistic fixture bundle and integration manifest"
```

---

### Task 5: 端到端校验（bootstrap/apply/slow smoke）

**Files:**
- Modify: `tests/test_memory_spike.py`
- Modify: `tests/test_openai_slow_verify.py`

- [ ] **Step 1: 写失败测试（realistic round 可 bootstrap+apply）**

```python
from security_analyst_agent.config import PROJECT_ROOT
from security_analyst_agent.memory_spike import bootstrap_memory_spike_database, apply_memory_spike_round
from security_analyst_agent.db import connect_db


def test_bootstrap_and_apply_realistic_round(tmp_path) -> None:
    db_path = tmp_path / "realistic.db"
    fixture_dir = PROJECT_ROOT / "fixtures" / "spike_memory_realistic"
    bootstrap_memory_spike_database(db_path, fixture_dir=fixture_dir)
    body = apply_memory_spike_round(db_path, "round_01_realistic", fixture_dir=fixture_dir)

    conn = connect_db(db_path)
    assert body["applied"] is True
    assert conn.execute("select count(*) from alerts").fetchone()[0] == 1000
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_memory_spike.py::test_bootstrap_and_apply_realistic_round -v`
Expected: `FAIL`

- [ ] **Step 3: 添加 openai slow verify realistic smoke（仅结构级）**

```python
# tests/test_openai_slow_verify.py

def test_load_realistic_manifest_and_round_specs() -> None:
    manifest = load_integration_manifest("hermes-slow-integration-realistic")
    assert manifest["fixture_dir"] == "fixtures/spike_memory_realistic"
    specs = resolve_round_specs(manifest)
    assert len(specs) == 5
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_memory_spike.py::test_bootstrap_and_apply_realistic_round tests/test_openai_slow_verify.py::test_load_realistic_manifest_and_round_specs -v`
Expected: `PASS`

- [ ] **Step 5: 提交**

```bash
git add tests/test_memory_spike.py tests/test_openai_slow_verify.py
git commit -m "test(fixtures): add realistic fixture bootstrap/apply and manifest smoke tests"
```

---

### Task 6: 生成真实样本并做最终回归

**Files:**
- Modify: `fixtures/spike_memory_realistic/rounds.json` (generated)

- [ ] **Step 1: 运行生成器产出 rounds.json**

Run:

```bash
uv run python -m security_analyst_agent.tools.generate_alert_fixture \
  --output-dir fixtures/spike_memory_realistic \
  --rounds 5 \
  --per-round 1000 \
  --chains 2 \
  --seed 20260419
```

Expected: 生成 `fixtures/spike_memory_realistic/rounds.json`，每轮 1000 条

- [ ] **Step 2: 运行核心测试**

Run:

```bash
uv run pytest -q tests/test_generate_alert_fixture.py tests/test_bootstrap.py tests/test_memory_spike.py tests/test_openai_slow_verify.py
```

Expected: 全部 PASS

- [ ] **Step 3: 运行一轮 realistic slow smoke（可选但推荐）**

Run:

```bash
uv run python -m security_analyst_agent.openai_slow_verify \
  --scenario hermes-slow-integration-realistic \
  --db-path /tmp/openai-slow-verify-realistic-01.db
```

Expected: 能完整跑完 5 轮（允许模型输出差异，但不应出现后端异常）

- [ ] **Step 4: 最终提交**

```bash
git add fixtures/spike_memory_realistic/rounds.json
git commit -m "chore(fixtures): generate realistic 5x1000 alert rounds with seed 20260419"
```

---

## Spec Coverage Self-Check

- [x] 5x1000 与 2 攻击链：Task 3 + Task 6
- [x] `attack_stage` 缺失落 `unknown` + `raw_attack_stage`：Task 1 + Task 3
- [x] 去诱导 alert_id/title：Task 3
- [x] realistic fixture + manifest：Task 4
- [x] 可复现 seed：Task 2 + Task 6
- [x] 基础与集成验证：Task 5 + Task 6
