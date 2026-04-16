# 案件渐进收敛（逻辑合并）设计

## 1. 目标

在告警早期证据不足时允许离散建案；随着后续告警、证据、画像持续更新，系统自动发现案间关联并逐步收敛，最终形成可回放的主攻击链视图。

本设计采用：

- 逻辑合并（保留原 `case_id`，不做物理迁移）
- 动态重选主案（canonical case）
- 两阶段自动策略（候选关联 -> 连续 3 轮高置信后确认合并）

## 2. 当前问题

- `case.upsert-batch` 仅按 `case_id` 幂等，缺少跨 case 归并机制。
- `assessment.upsert-batch` 为结构化写入，不包含后端独立关联推断。
- 虽然已有画像候选评分能力，但没有“run 级自动归并”主路径。

## 3. 设计原则

- 前期离散，后期收敛，不强制一次性判定真相。
- 合并可解释、可审计、可回放、可撤销。
- 优先最小改动：在现有工具流上新增“run 收尾后的后端收敛”。

## 4. 数据模型变更

### 4.1 `cases` 新增字段

- `canonical_case_id text`：该 case 所属主案 ID（默认自身）
- `merged_into_case_id text`：若已归并，指向当前主案 ID（主案为 `null`）
- `merge_state text`：`standalone` / `candidate` / `merged`
- `merge_updated_at text`

### 4.2 新表 `case_relations`

用于记录 case 对之间的候选关系与连续轮次状态。

- `relation_id text primary key`
- `left_case_id text not null`
- `right_case_id text not null`
- `relation_type text not null`（初始仅 `possible_same_intrusion`）
- `score real not null`
- `streak_count integer not null`
- `status text not null`（`candidate` / `confirmed` / `rejected`）
- `last_run_id text`
- `last_reason text not null`
- `supporting_alert_ids_json text not null`
- `supporting_evidence_ids_json text not null`
- `first_seen_at text not null`
- `last_seen_at text not null`

约束：

- `(left_case_id, right_case_id, relation_type)` 唯一，且按字典序存储 pair。

### 4.3 新表 `case_merge_events`

记录每次主案重选/逻辑合并操作。

- `event_id text primary key`
- `occurred_at text not null`
- `run_id text`
- `cluster_id text not null`
- `old_canonical_case_id text`
- `new_canonical_case_id text not null`
- `affected_case_ids_json text not null`
- `reason text not null`
- `detail_json text not null`

## 5. 关系评分与两阶段状态机

### 5.1 候选关系评分（run 收尾触发）

在同一 run 内，针对“被触达/更新的 open case”两两打分：

- 资产重叠（`case_alert_links` + `alerts.asset_id`）
- 阶段连续性（`current_stage` 演进相邻/可解释）
- IOC/画像重叠（IP、已沉淀 observation、关键证据类型）
- 时间因果（两案关键事件时间接近或前后承接）
- 证据桥接（同一 `evidence_type` 或共享 supporting references）

### 5.2 阈值

- `candidate_threshold = 0.68`
- `merge_threshold = 0.78`
- `required_streak = 3`

### 5.3 状态转移

- `score < candidate_threshold`：不入候选或候选回退
- `candidate_threshold <= score < merge_threshold`：`candidate`，`streak` 仅在连续 run 达标时递增
- `score >= merge_threshold` 且连续 `3` 轮达标：`confirmed`，触发逻辑合并

## 6. 动态主案重选

在一个 confirmed 连通分量（cluster）里计算每个 case 的 `canonical_score`：

- 时间线覆盖度（节点数、阶段深度）
- 证据完整度（证据数量、关键证据类型）
- 关系中心性（与其它 case confirmed/candidate 强度）
- 近期活跃度（最近关键事件时间）
- 画像上下文完整度（画像数、关键 observation 完整性）

选最高分作为 `canonical_case_id`，其余 case：

- `merged_into_case_id = canonical_case_id`
- `canonical_case_id = canonical_case_id`
- `merge_state = merged`

主案自身：

- `canonical_case_id = self.case_id`
- `merged_into_case_id = null`

## 7. 读写语义

### 7.1 写路径

- `case.link-alert-batch` / `case.update-risk` 在执行前解析 `canonical_case_id`。
- 若 payload 指向已 merged 子案，写入自动重定向到主案并返回 warning（保留可解释性）。

### 7.2 读路径

- `case.get` 默认返回“主案聚合视图”，并附带子案列表（`related_case_ids`）。
- `case.timeline` 默认读取主案 + 子案按时间合并视图（可加开关仅主案本体）。

## 8. 与攻击者画像收敛的关系

V0 不做物理画像合并；先做“跨 cluster 候选增强”：

- `actor.case-find-candidates` 可在同 canonical cluster 内检索候选画像。
- 新告警优先复用同 cluster 画像，减少“新 IP -> 新画像”。

## 9. 审计与可观测性

- `case_relations` 保留每轮评分、证据引用、streak 变化。
- `case_merge_events` 保留每次主案重选与影响范围。
- `case_changes` 追加 `action=case_merge_reselect` / `case_merge_apply`。

## 10. 回滚策略

- 合并为逻辑操作，可通过 `case_merge_events` 逆向恢复字段状态。
- 不迁移底层告警/证据原始归属，降低回滚复杂度。

## 11. 验收标准

- 同一攻击链被拆分为多个 case 的场景，连续 3 轮后自动收敛为同一 canonical。
- 收敛后 `case.get` 与 `case.timeline` 可还原主链，且保留子案来源可追溯。
- 误合并可通过事件日志回滚，不丢历史证据与审计链路。
