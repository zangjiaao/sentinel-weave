# 2026-04-19 Realistic Alert Fixture Generator Design

## 1. 背景与目标

当前 `fixtures/spike_memory*` 告警样本偏“演示型”：
- `alert_id` 含较强语义（易被模型/人工反向猜链路）
- `title` 偏剧情描述，不够贴近真实安全产品告警文本
- 样本规模偏小，难以验证高噪音下的鲁棒性

本设计目标是在不破坏现有验证链路的前提下，新增一套“真实风格+大规模+可复现”的 fixture 生成能力。

**目标产物**：
- 生成 `5 轮 x 每轮 1000 条`（共 5000 条）告警数据
- 内置 `2` 条攻击链并分散在 5 轮中推进
- 噪音大量混入，验证 Agent 在噪音中提取高价值信号
- 支持固定 `seed`，可复现同一数据集

## 2. 范围与非目标

### 2.1 范围
- 新增告警 fixture 生成脚本（模板驱动）
- 新增 realistic fixture 目录与 manifest
- 在 `alerts` 增加 `raw_attack_stage` 字段（可空）
- 保持现有 `spike_memory` 与 `spike_memory_expanded` 不变

### 2.2 非目标
- 不改 Agent 推理逻辑/提示词
- 不重构 case convergence 评分体系
- 不引入复杂状态机仿真（后续可演进）

## 3. 方案对比与决策

### 方案 A：模板驱动（选定）
- 攻击模板 + 噪音模板 + 轮次配比 + 时间分布
- 优点：可控、可复现、便于断言
- 缺点：真实性中等，行为模式相对规则

### 方案 B：状态机仿真
- 优点：真实性高
- 缺点：实现复杂，调参成本高

### 方案 C：纯分布随机
- 优点：开发快
- 缺点：可解释性弱，失败难定位

**决策**：先落地 A，后续按需要吸收 B 的状态推进能力。

## 4. 数据模型设计

## 4.1 alerts 字段策略
当前业务依赖 `alerts.attack_stage`（`NOT NULL`）。采用“兼容增强”：
- 保留 `attack_stage` 必填
- 新增 `raw_attack_stage`（可空）

规则：
- 上游有阶段值：
  - `attack_stage` = 归一化值（如 `recon/persistence/...`）
  - `raw_attack_stage` = 原始值
- 上游无阶段值：
  - `attack_stage = 'unknown'`
  - `raw_attack_stage = null`

该策略保证：
- 不破坏现有查询/聚类/评分逻辑
- UI/分析可区分“真实缺失”与“归一化结果”

## 5. 生成规则

## 5.1 总体规模
- rounds: `5`
- each_round_alerts: `1000`
- total: `5000`

## 5.2 结构配比（默认）
- 噪音：约 `97%`
- 攻击信号：约 `3%`（两条链路总计）

> 注：比例支持通过参数调整，但默认固定，确保团队复盘口径一致。

## 5.3 攻击链设计（两条）
- 链 A（API 资产族）
  - R1 recon
  - R2 exploit + persistence
  - R3 command_execution
  - R4 lateral_prep
  - R5 reactivation/command_execution
- 链 B（Billing 资产族）
  - R1 recon
  - R2 exploit_attempt
  - R3 persistence
  - R4 quiet/low-activity
  - R5 reactivation + command_execution

要求：
- 两条链共享“现实中的不确定性”，但不直接喂结论
- 在资产、时间、IP 轮换上保留可还原连续性

## 5.4 噪音模板池
至少覆盖以下类别：
- 目录探测/参数探测
- 弱口令探测/扫描器重复命中
- 健康检查/监控探针/发布流量误报
- 代理重试/低质量 bot 探测

噪音特征：
- 大量 `low` + 少量 `medium`
- `attack_stage` 多为 `recon` 或 `unknown`
- 标题/源 IP 呈现“看起来像真告警但价值低”的分布

## 5.5 标题与 ID 去诱导化
- `alert_id`：随机化/序列化，无链路语义（不含 `chain/r1/r2`）
- `title`：更贴近真实检测命名（产品/模块/行为风格）
- 不在标题中硬编码“攻击者开始横向移动”等剧情词

## 5.6 时间分布与混入
- 每轮有固定时间窗口（例如 15-30 分钟）
- 攻击信号随机落点插入噪音中
- 同一链路的关键事件保留时间先后与阶段推进

## 6. 文件与代码落地

### 6.1 新增文件
- `src/security_analyst_agent/tools/generate_alert_fixture.py`
- `fixtures/spike_memory_realistic/base_bundle.json`
- `fixtures/spike_memory_realistic/rounds.json`（由脚本生成）
- `docs/runbooks/manifests/hermes-slow-integration-realistic.json`

### 6.2 修改文件
- `src/security_analyst_agent/db.py`
  - 为 `alerts` 增加 `raw_attack_stage`
- `src/security_analyst_agent/memory_spike.py`
  - 兼容加载 `raw_attack_stage` 字段（若存在）

## 7. 生成器接口

命令行示例：

```bash
uv run python -m security_analyst_agent.tools.generate_alert_fixture \
  --output-dir fixtures/spike_memory_realistic \
  --rounds 5 \
  --per-round 1000 \
  --chains 2 \
  --seed 20260419
```

关键参数：
- `--rounds` 默认 `5`
- `--per-round` 默认 `1000`
- `--chains` 默认 `2`
- `--seed` 默认固定值（可覆盖）

## 8. 测试与验证

新增测试：
1. 生成器结构测试
   - rounds 数量正确
   - 每轮条数正确
   - 总条数正确
2. 字段合法性测试
   - `attack_stage` 永不为空
   - `raw_attack_stage` 可空
   - stage 缺失时 `attack_stage='unknown'`
3. 去诱导性测试
   - `alert_id` 不含 `chain/r1/r2` 等模式
4. 统计分布测试
   - 噪音比例、severity 分布、链路分布在阈值范围内
5. 集成 smoke
   - bootstrap + apply round + openai/hermes slow 验证至少可跑通一轮

## 9. 风险与缓解

- 风险：过多 `unknown` stage 影响关系评分
  - 缓解：攻击信号保留关键阶段；噪音才大量使用 `unknown`
- 风险：随机性导致评估波动
  - 缓解：默认固定 seed；CI 使用固定 seed
- 风险：样本“太干净”
  - 缓解：加入中等噪音、伪相关噪音、IP 轮换噪音

## 10. 分阶段交付

- Phase 1（本次）
  - 模板驱动生成器 + realistic fixture + manifest + 基础测试
- Phase 2（后续）
  - 引入轻量状态推进（A+），增强静默期/反复活跃真实性

## 11. 验收标准

满足以下即通过：
- 能稳定生成 `5x1000` 数据
- 两条攻击链在高噪音中仍可被 case 系统还原为两条主链（允许子案并入）
- 不破坏现有 fixture 与测试
- 可通过固定 seed 复现实验结果
