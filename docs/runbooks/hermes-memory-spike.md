# Hermes Memory Spike Runbook

## Scope

- 只用于验证 `Hermes` 的长期记忆价值
- 不用于真实设备接入
- 数据库仍是事实源，`Hermes memory` 只看作工作记忆
- 默认演练数据库路径采用 `./memory-spike.db`，避免覆盖现有 `./spike.db`

## Expanded Scenario（高噪音 + 双攻击链）

如果要压测“样本数量与复杂度”，可直接使用扩展 slow 场景：

```bash
uv run python -m security_analyst_agent.hermes_slow_verify \
  --scenario hermes-slow-integration-expanded \
  --db-path /tmp/hermes-slow-verify-case-convergence-expanded.db \
  --keep-artifacts
```

说明：

- 场景 manifest：`docs/runbooks/manifests/hermes-slow-integration-expanded.json`
- 样本目录：`fixtures/spike_memory_expanded`
- 覆盖特征：双攻击链并行推进、静默轮、大批量噪音轮、再激活轮

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

## Audit & Context Checks

多轮跑完后，建议用以下命令检查 Agent 实际行为轨迹（不是只看自然语言报告）：

```bash
uv run python -m security_analyst_agent.cli audit.tool-calls --db-path ./memory-spike.db --limit 30
uv run python -m security_analyst_agent.cli audit.alert-decisions --db-path ./memory-spike.db --limit 30
uv run python -m security_analyst_agent.cli audit.case-changes --db-path ./memory-spike.db --limit 30
uv run python -m security_analyst_agent.cli audit.escalations --db-path ./memory-spike.db --limit 30
```

查看跨会话摘要与巡检状态：

```bash
uv run python -m security_analyst_agent.cli context.case-digest --db-path ./memory-spike.db --case-id case_demo_001
uv run python -m security_analyst_agent.cli context.patrol-state --db-path ./memory-spike.db
```

按单次巡检回放（先取 `run_id` 再过滤审计日志）：

```bash
sqlite3 ./memory-spike.db "select run_id, trigger_source, status, started_at, finished_at from patrol_runs order by started_at desc limit 5;"
uv run python -m security_analyst_agent.cli audit.tool-calls --db-path ./memory-spike.db --run-id <run_id> --limit 100
uv run python -m security_analyst_agent.cli audit.alert-decisions --db-path ./memory-spike.db --run-id <run_id> --limit 100
uv run python -m security_analyst_agent.cli audit.case-changes --db-path ./memory-spike.db --run-id <run_id> --limit 100
uv run python -m security_analyst_agent.cli audit.escalations --db-path ./memory-spike.db --run-id <run_id> --limit 100
```

说明：`mcp_auto` 巡检批次会在以下时机自动写入 `finished_at`：
- `alert.fetch` 返回 0 条（空队列）
- 执行 `alert.ack` 后队列被清空（`new/open` 为 0）
