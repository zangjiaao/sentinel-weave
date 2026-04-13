# 网络安全辅助 Agent PoC 设计（v0）

- 日期：2026-04-12
- 阶段：PoC / 高层方案
- 状态：已完成首轮讨论，待细化子模型

## 1. 背景

目标用户拥有较多公网 IP、业务系统（Web、APP）以及多类安全设备（如 WAF、DPI、态势感知、EDR、主机审计等）。当前主要问题包括：

- 安全产品众多，告警日志海量，真实攻击容易被噪音淹没
- 相同资产可能在不同设备中表现为不同 IP、域名、系统名，人工关联成本高
- 恶意 IP/IOC 分析依赖第三方情报平台，查询繁琐
- 分析结论与报告编写耗时，难以快速响应
- 攻击者往往长期打点，单条告警难以还原完整攻击活动

因此，需要一个偏蓝队值守与研判方向的辅助 Agent，持续理解资产和历史攻击背景，对新告警进行综合评估，并在必要时调用工具补充证据，最终输出可信的攻击研判结论。

## 2. PoC 目标与非目标

### 2.1 目标

PoC 阶段聚焦验证以下闭环：

1. 导入并结构化保存客户资产清单
2. 通过工具层接入安全设备告警
3. 对告警做初步过滤、归并和案件化管理
4. 结合历史记录、资产上下文和情报查询做综合研判
5. 识别高价值真实攻击活动并触发通知
6. 生成值守快报或分析报告草稿

### 2.2 非目标

PoC 阶段暂不追求以下能力：

- 自动下发拦截、封禁、策略变更等处置动作
- 覆盖所有安全设备与所有日志类型
- 复杂多 Agent 协作编排
- 完整 SOC 平台级前端
- 高精度、全自动风险评分体系

## 3. 已确认设计决策

- 当前 Spike 使用 `Hermes` 验证长期巡检工作流，但核心能力必须保持 `runtime-neutral`
- `Hermes` 的定位是可替换的 `Runner Adapter`，不是业务核心、事实源或唯一记忆系统
- 采用“案件/攻击活动中心”而不是“单告警中心”的研判视角
- 采用“确定性流水线 + 单主 Agent”的混合架构
- Agent 主要负责研判、补证、总结，不负责全部数据处理
- 工具层优先做只读 CLI，并统一输出 JSON
- 结构化状态存数据库，不能只依赖聊天上下文记忆
- 通知由规则和 Agent 共同决定，不能仅依赖单一 IP 风险分

### 3.1 Runtime Neutral 原则

PoC 可以使用 `Hermes`，但不能把系统能力写死在 `Hermes` 里。后续如果替换为 `OpenAI SDK Runner` 或自研轻量运行时，核心分析流程、数据状态和审计能力仍应可复现。

必须满足：

- 资产、告警、案件、证据、攻击者画像、评分、反馈等事实状态必须进入系统数据库
- `Hermes memory` 只允许保存巡检摘要、关注点、临时假设、待补证问题等工作记忆
- Tool 合约独立于 `Hermes`，同一套 Tool 应能被 CLI、MCP、`Hermes Runner` 或 `OpenAI SDK Runner` 调用
- Skill、SOP、Prompt 模板必须以仓库文件作为真源，不能只存在于本机 `~/.hermes` 配置
- 每轮 Agent 运行的输入、工具调用、输出、写入状态应进入系统可审计记录，不能只依赖 `Hermes session`

判断是否过度依赖 `Hermes` 的红线：

- 换掉 `Hermes` 后案件状态、用户反馈或评分历史丢失
- 告警关联、噪音处理或报告模板只存在于 `Hermes` 私有配置
- 历史分析无法通过数据库状态和 Tool 调用记录复现
- `Hermes memory` 成为事实证据库或唯一审计来源

## 4. 总体架构

PoC 采用以下六层结构：

### 4.1 Agent 层

由一个主研判 Agent 负责：

- 读取案件摘要、资产背景、历史记录
- 判断是否为真实攻击或高可疑活动
- 决定是否补查设备详情、主机行为、IP/IOC 情报
- 输出研判结论、证据摘要和报告草稿

### 4.2 工具层

由人工适配不同设备的 Web 管理接口，封装为只读 CLI。工具层负责：

- 拉取告警
- 查看告警详情
- 搜索相关日志与请求
- 查询资产信息
- 查询威胁情报
- 发送通知

工具层必须满足以下原则：

- 支持 `--json`
- 支持 `--since`、`--limit`、`--cursor`
- 默认返回摘要，详情按需获取
- 输出字段稳定，便于 Skill 解释和 Agent 调用

### 4.3 Skill 层

Skill 不只是介绍命令怎么用，还要告诉 Agent：

- 什么时候应该调用哪个工具
- 哪些字段可信，哪些字段容易误导
- 常见误报模式和已知噪音特征
- 哪些查询成本高，不应频繁调用
- 哪些证据足以支持某类攻击动作判断

### 4.4 数据处理层

尽量使用确定性逻辑完成：

- 告警标准化
- 去重与聚合
- 资产映射
- 命中误报/噪音规则
- 基础案件归并
- 摘要生成

### 4.5 状态存储层

用于保存长期研判上下文：

- 资产主数据与别名
- 告警与原始证据引用
- 案件/攻击活动
- IP/IOC 情报缓存
- 误报规则
- Agent 研判记录
- 通知记录

### 4.6 输出层

PoC 阶段输出两类结果：

- 值守快报：用于第一时间通知
- 分析报告草稿：用于复盘和正式上报

### 4.7 Runner Adapter 与 Hermes 接入策略

PoC 阶段确认先采用 `Hermes Agents` 作为巡检型 Agent 运行时，用于验证长期巡检、Skill 约束和工作记忆。但从架构上，`Hermes` 只属于 `Runner Adapter` 层。

`Runner Adapter` 的职责是：

- 接收后端触发的巡检、案件评估或报告生成任务
- 组装任务所需的策略文件、上下文摘要和 Tool 能力
- 调用模型并执行受控 Tool
- 将结论、记忆摘要、工具调用和状态变更建议回写给系统

当前可选 Runner 包括：

- `Hermes Runner`：适合持续巡检、Skill 执行、跨轮次工作记忆
- `OpenAI SDK Runner`：适合较轻的导入清洗、报告生成、单次分析或后续自研 runtime 过渡

Hermes 的定位应明确为：

- 编排层
- 研判层
- 记忆增强层
- 可替换运行时适配层

而不是：

- 原始日志存储层
- 海量告警标准化流水线
- 主数据库
- 规则引擎

也就是说，Hermes 适合做“会思考、会调用工具、会形成结论”的部分，不适合承担“大吞吐、强约束、强审计”的底层数据处理。

### 4.8 Hermes 负责什么

PoC 阶段建议由 Hermes 负责：

- 读取案件摘要、资产背景、历史记录
- 决定下一步是否补证
- 调用外部 Tool 查询设备详情、情报、证据
- 生成案件判断、通知草稿、报告草稿
- 维护偏“摘要型”的长期记忆
- 在定时调度下周期性巡检案件或新告警摘要

### 4.9 Hermes 不负责什么

PoC 阶段不建议由 Hermes 直接负责：

- 逐条解析海量原始告警
- 原始日志长期存储
- 设备字段标准化主流程
- 去重、聚合、归并的主执行逻辑
- 评分主计算逻辑
- 误报规则匹配主流程

这些能力应由确定性组件和数据库承担，Hermes 通过 Tool 访问这些结果。

### 4.10 Hermes 周边组件

如果采用 Hermes，系统建议分为两类组件：

- **确定性组件**
  - `source runner`
  - `upload processor`
  - `parser engine`
  - `normalizer`
  - `case aggregator`
  - `rule matcher`
  - `database`

- **Hermes Agent 层**
  - `main analyst agent`
  - 可选的 `report agent`
  - 可选的 `intel lookup agent`

PoC 第一阶段建议只有一个 `main analyst agent`，不要一开始就引入复杂多 Agent 协作。

### 4.11 Hermes 接入模式优先级

为了避免一开始就被某个 Agent 引擎的私有接口绑定，PoC 阶段建议按以下优先级接入 Hermes：

#### 4.11.1 优先模式 A：Hermes 直接注册本地 CLI Tool

首选模式是让 Hermes 直接调用本地 CLI Tool，即：

`Hermes Agent -> CLI Tool -> JSON 响应 -> Hermes Agent`

特点：

- 接入最薄，便于快速验证
- Tool 调试简单，可先脱离 Hermes 单独测试
- 易于审计，每次调用都可落日志
- 未来迁移到其他 Agent 运行时成本较低

这也是当前 PoC 计划默认采用的接入方式。

#### 4.11.2 备选模式 B：本地适配层封装 CLI 为 HTTP / MCP

如果 Hermes 运行时本身不能稳定调用本地 CLI，或者其 Tool 能力更偏向 `HTTP` / `MCP`，则建议增加一层轻适配：

`Hermes Agent -> local adapter -> CLI Tool / Python service -> JSON 响应`

这层适配器的职责应尽量薄，仅负责：

- 鉴权与运行环境隔离
- 参数转发
- 超时与重试控制
- stdout / stderr 到结构化 JSON 的转换

不建议在适配层中再加入复杂业务逻辑，否则容易形成第二套不透明系统。

#### 4.11.3 不建议模式 C：一开始深度嵌入 Hermes 私有 SDK

PoC 第一轮不建议直接做深度 SDK 绑定式集成，例如：

- 在业务代码里大量写 Hermes 私有对象模型
- 让 Tool、记忆、调度都强依赖 Hermes 内部抽象
- 让 Hermes 直接承担数据库与原始告警处理职责

原因是 PoC 目标首先是验证“工作流能否跑通”，而不是验证“是否深度绑定某个引擎”。

#### 4.11.4 当前建议

因此，当前方案建议：

- **第一阶段**：采用模式 A，最快跑通闭环
- **如 Hermes 不支持本地 CLI Tool**：退到模式 B
- **明确不做**：模式 C

这样既能尽快验证 Hermes 的可用性，也不会把后续架构锁死。

## 5. 核心工作流

### 5.1 资产初始化

1. 用户提供资产清单文件
2. Agent 调用资产导入工具完成结构化入库
3. 保存公网 IP、内网 IP、域名、系统名、业务归属、重要性、责任人等信息
4. 若发现可能为同一资产的多个别名，先生成归并候选，不自动覆盖主数据

### 5.2 告警获取与导入

1. 调度器或 Agent 可定时调用设备 CLI / API 获取新增告警
2. 用户也可通过手工上传方式导入设备导出的告警文件、日志文件或样例告警
3. 无论来自持续拉取还是手工上传，都进入统一的标准化与入库流程
4. 原始日志和原始请求不直接塞给 Agent，而是保存引用或切片证据

### 5.3 初步过滤

在 Agent 参与前优先完成：

- 同类重复告警去重
- 已知扫描器特征识别
- 已确认误报匹配
- 明显失败探测归类
- 基于资产映射补充上下文

过滤后的每条记录都应保留原因，确保后续可审计。

### 5.4 案件归并

将新告警归并到“攻击活动/案件”中，而不是逐条独立分析。归并参考维度包括：

- 源 IP / 源实体
- 目标资产
- 时间窗口
- 攻击类型
- URL、接口、规则命中、漏洞类型
- 设备来源

案件归并不应仅依赖单个 IP，而应围绕以下四个锚点综合判断：

- `asset`：被攻击的业务资产或系统
- `actor_entity`：攻击实体，由多个身份线索和行为特征拼接而成
- `attack_artifact`：攻击产物，例如 WebShell、落地文件、回连地址、恶意域名、特征化请求路径
- `timeline`：跨时间的攻击活动轨迹

其中：

- `actor_entity` 不等于单个 IP，更接近“攻击者画像”或“攻击活动实体”
- `attack_artifact` 是跨天、跨 IP、跨设备串联攻击链的关键对象
- `timeline` 用于识别长期打点、多阶段渗透和案件续接

### 5.4.1 攻击者画像与攻击实体

系统应支持维护“可跨案件复用的全局画像库”，但 PoC 阶段只需要实现轻量版本。其目标不是证明真实世界中的某个自然人身份，而是识别：

- 哪些事件高度可能属于同一攻击活动
- 哪些不同案件可能共享同一攻击基础设施、手法或操作者
- 当前证据足以将关联置信度提升到什么程度

攻击实体或攻击者画像建议至少包含以下层次：

- 观测层：`observed_source_ip`、`claimed_client_ip`、`asn`、`geo`、`user_agent`、`ja3/ja4`、域名、会话标识
- 行为层：扫描路径模式、payload 特征、漏洞利用风格、命令执行习惯、内网扫描节奏
- 关系层：打过哪些资产、关联过哪些攻击产物、关联过哪些案件
- 判断层：当前置信度、关键证据、反证、最近活跃时间、当前推断阶段

### 5.4.2 攻击产物

系统应支持记录能串联攻击链的重要攻击产物，例如：

- WebShell 文件路径
- WebShell 文件名或 hash
- 访问 WebShell 的 URI
- 恶意上传文件
- 回连域名、C2 地址
- 特征化口令、参数名、请求模板

攻击产物的主要作用是：

- 帮助识别不同时间、不同 IP 的行为是否属于同一次入侵活动
- 帮助把边界设备告警与主机侧异常关联到一起
- 为案件时间线和报告提供强证据节点

### 5.4.3 案件关联理由

案件归并、案件续接和画像关联都必须保留“为什么这样连”的结构化理由。建议记录：

- `link_type`：如 `same_infra`、`same_ttp`、`same_artifact`、`same_targeting`、`same_asset_progression`
- `link_confidence`
- `link_reason`
- `evidence_refs`

这样做的目的是避免系统只给结论不给依据，也便于人工复核和后续校准。

### 5.5 Agent 研判

主 Agent 基于以下输入做判断：

- 资产摘要
- 当前案件摘要
- 最近时间线
- 历史相似案件
- 关键证据片段

研判输出应至少包括：

- 是否更像噪音、失败探测、疑似攻击、已确认攻击
- 攻击对象和影响资产
- 攻击动作或攻击阶段推断
- 当前证据强度和不确定性
- 是否需要补证

### 5.6 情报补证

仅在必要时调用情报工具，例如：

- 告警强度较高但证据不足
- 目标资产重要
- 源 IP 多次命中不同资产
- 涉及漏洞利用、RCE、WebShell、爆破、反连等高危行为

情报查询结果进入缓存，避免重复调用。

### 5.7 动态风险评估

PoC 不采用单一“攻击 IP 总分”，而拆分为四个维度：

- `ip_risk`：IP 或实体本身的恶意倾向
- `case_confidence`：当前案件是真实攻击的置信度
- `asset_criticality`：目标资产的重要程度
- `activity_freshness`：近期活动持续性

其中：

- 沉默一段时间可以降低活跃度，但不直接洗白历史风险
- 历史恶意记录不能单独决定当前案件结论

### 5.7.1 可解释动态评分

评分系统的目标不是生成一个黑盒分数，而是让用户理解：

- 当前案件为什么是这个风险等级
- 风险为什么上升或下降
- 当前是否值得立即处理

因此评分系统必须满足以下原则：

- 动态：分数会随着新证据持续变化
- 可解释：每次变化都能说明原因
- 可拆解：用户可看到各维度贡献
- 可追溯：可以回看历史变化轨迹
- 可校准：用户可反馈并修正规则或权重

### 5.7.2 评分维度展示

评分系统内部应维护多维度判断，但前台默认展示不应过于复杂。系统内部建议至少维护以下维度：

- `case_confidence`
- `asset_criticality`
- `attack_stage_severity`
- `evidence_quality`
- `activity_freshness`
- `blast_radius`

在用户界面中，默认应优先展示：

- 当前总体等级
- 最近升分/降分记录
- 一个“查看评分依据”入口

当用户进入下钻层时，再展示各维度明细。对于每个维度，系统应尽量提供：

- 当前值
- 近期趋势
- 最近变化原因
- 对应关键证据

### 5.7.3 评分事件

每次案件风险变化都应生成可审计的评分事件，建议包含：

- `score_event_id`
- `case_id`
- `changed_at`
- `score_dimension`
- `delta`
- `reason_code`
- `reason_text`
- `evidence_refs`
- `trigger_source`

典型示例如下：

- `+15`：同一资产短时间出现高危漏洞利用特征
- `+20`：发现 WebShell 落地证据
- `+10`：边界设备与主机设备形成交叉印证
- `-12`：命中已知高误报规则
- `-8`：长时间无后续活动

### 5.7.4 风险等级展示

PoC 阶段建议将分值映射为较直观的风险等级，而不是过度强调精确数字。可采用类似分层：

- `0-20`：低风险
- `21-40`：观察
- `41-60`：可疑
- `61-80`：高风险
- `81-100`：紧急

最终界面或报告中应优先展示“当前等级 + 变化原因 + 关键证据”，分数仅作为辅助表达。

### 5.7.5 用户校准

如果用户认为评分不符合直觉或实际情况，系统应允许以下校准动作：

- 修正误报规则
- 修正设备字段映射
- 修正资产归并关系
- 修正案件关联关系
- 调整规则质量画像或本地噪音权重

PoC 阶段不建议让用户直接修改复杂评分公式，更适合通过修正规则、标签和关联关系来间接影响评分结果。

### 5.8 通知与报告

当案件满足综合条件时触发通知，例如：

- 高价值资产被打
- 多设备证据相互印证
- 疑似成功利用或边界突破
- 案件置信度较高

通知内容应包含：

- 攻击源
- 目标资产
- 攻击动作摘要
- 关键证据
- 当前判断与建议

随后 Agent 可生成值守快报或完整分析报告草稿。

## 6. 工具层设计

### 6.1 资产工具

- `asset import`
- `asset list`
- `asset get`
- `asset search`
- `asset propose-link`
- `asset update-candidate`

### 6.2 告警工具

- `alert fetch`
- `alert list`
- `alert detail`
- `alert search`
- `alert raw-evidence`

### 6.3 设备工具

根据不同设备分组封装，例如：

- `waf fetch-alerts`
- `waf get-alert-detail`
- `waf search-requests`
- `dpi fetch-events`
- `dpi search-flow`
- `edr search-host-events`
- `siem search-alerts`

### 6.4 案件工具

- `case create`
- `case list`
- `case get`
- `case append-evidence`
- `case update-status`
- `case timeline`
- `case summarize`
- `case link-actor`
- `case link-artifact`
- `case explain-link`

建议案件状态包括：

- `observing`
- `likely_noise`
- `suspicious`
- `confirmed_attack`
- `needs_review`
- `closed`

### 6.5 情报工具

- `intel ip-lookup`
- `intel domain-lookup`
- `intel hash-lookup`
- `intel cache-get`
- `intel cache-refresh`

### 6.6 攻击者画像与攻击产物工具

- `actor list`
- `actor get`
- `actor search`
- `actor propose-link`
- `artifact list`
- `artifact get`
- `artifact link-case`
- `artifact search`

### 6.7 噪音与误报工具

- `noise rule-list`
- `noise rule-add`
- `noise match`
- `noise mark-false-positive`
- `noise explain`

### 6.8 通知工具

- `notify preview`
- `notify send`
- `notify history`

### 6.9 报告工具

- `report draft`
- `report export-md`
- `report export-docx`

### 6.10 接入中心与解析规则工具

- `source list`
- `source get`
- `source upsert`
- `source enable`
- `source disable`
- `source run-history`
- `upload create`
- `upload status`
- `upload list`
- `parser profile-list`
- `parser profile-get`
- `parser profile-update`
- `parser replay-preview`

### 6.11 Hermes 第一批 Tool 合约（建议）

如果 PoC 第一阶段采用 Hermes，建议先只接入以下最小 Tool 集，不要一开始把所有工具都挂给 Agent。

#### 6.11.1 资产域 Tool

- `asset.search`
- `asset.get`
- `asset.list`
- `asset.propose-link`

用途：

- 根据 IP、域名、主机名定位资产
- 获取资产详情供案件研判使用
- 提出归并候选而不是直接改主数据

#### 6.11.2 告警与案件域 Tool

- `alert.fetch`
- `alert.detail`
- `case.list`
- `case.get`
- `case.timeline`
- `case.update-status`
- `case.explain-link`

用途：

- 获取新告警摘要
- 查看某条告警详情
- 读取案件列表与案件详情
- 获取案件时间线
- 在人工或自动研判后更新案件状态
- 解释为何某画像或产物被关联到当前案件

#### 6.11.3 证据与画像域 Tool

- `evidence.list`
- `evidence.get`
- `actor.get`
- `artifact.get`

用途：

- 获取关键证据切片
- 查看攻击者画像摘要
- 查看攻击产物详情

#### 6.11.4 情报域 Tool

- `intel.lookup`
- `intel.cache-get`

用途：

- 按需查询 IP / 域名 / Hash 等情报
- 读取历史缓存，避免重复查询

#### 6.11.5 输出域 Tool

- `notify.preview`
- `notify.send`
- `report.draft`
- `report.export`

用途：

- 生成通知草稿
- 发送通知
- 生成报告草稿
- 导出报告

#### 6.11.6 接入域 Tool

- `source.list`
- `source.run-history`
- `upload.list`
- `upload.status`
- `parser.profile-get`

用途：

- 让 Hermes 知道当前数据源是否健康
- 让 Hermes 在接入异常时能解释“为什么数据不完整”
- 在样例映射或规则异常时辅助诊断

### 6.12 Tool 设计原则

为了让 Hermes 稳定使用，Tool 合约建议遵守以下原则：

- 返回结构化 JSON
- 默认返回摘要，不返回超长原文
- 所有高成本查询都应支持分页、limit、时间窗
- Tool 命名按业务域组织，而不是按 Hermes 内部抽象组织
- Tool 输出要可审计、可重放、可缓存

### 6.13 Hermes Spike 验收标准

在正式进入实现前，建议先做一个 Hermes 适配性 Spike。只要能跑通以下链条，就可以确认 Hermes 适合当前 PoC：

- 读取一个已存在案件
- 调用资产 Tool 获取目标系统信息
- 调用情报 Tool 补查攻击源
- 调用证据 Tool 查看关键证据
- 生成通知草稿
- 生成报告草稿

如果 Hermes 在上述链条中表现稳定，则说明它适合担任当前 PoC 的编排和研判引擎。

### 6.14 Hermes Tool 输入输出合约（v0）

PoC 阶段不需要一次性冻结所有 Tool 细节，但第一批 Tool 至少应做到：

- 参数稳定，避免同义参数在不同 Tool 中反复变化
- 输出结构统一，便于 Hermes 形成稳定调用习惯
- 高成本查询可分页、可限流、可缓存
- 写操作默认审慎，必须可审计、可解释、可回放

#### 6.14.1 通用输入约定

建议第一批 Tool 尽量复用以下通用输入字段：

- `time_range`：`{ from, to, timezone }`
- `limit`：默认 `20`，建议最大不超过 `100`
- `cursor`：用于翻页，避免一次取全量
- `filters`：结构化筛选条件，而不是长自然语言
- `include`：显式声明是否附带 `evidence`、`timeline`、`aliases` 等扩展信息
- `sort`：如 `{ by: "severity", order: "desc" }`
- `dry_run`：所有写操作 Tool 均建议支持
- `reason`：所有写操作 Tool 均要求填写原因
- `operator`：建议默认标记为 `agent`

这样做的目的不是追求“统一而统一”，而是为了让 Hermes 在多 Tool 之间迁移时不必反复学习参数风格。

#### 6.14.2 通用输出约定

建议所有 Tool 的响应结构尽量收敛为以下骨架：

```json
{
  "ok": true,
  "summary": "对本次结果的简短摘要",
  "data": {},
  "warnings": [],
  "refs": {
    "case_ids": [],
    "alert_ids": [],
    "asset_ids": [],
    "evidence_ids": [],
    "source_ids": []
  },
  "page": {
    "next_cursor": null,
    "has_more": false
  },
  "meta": {
    "cache_hit": false,
    "partial": false,
    "generated_at": "2026-04-13T10:00:00+08:00"
  }
}
```

约束建议如下：

- `summary` 用于让 Hermes 快速理解结果，不应省略
- `data` 承载结构化主体
- `warnings` 用于提示“结果不完整”“上游异常”“命中旧缓存”等情况
- `refs` 用于把结果挂回案件、告警、证据、资产等实体
- `page` 用于大结果集翻页
- `meta.partial=true` 表示本次结果为部分成功，不可当作完整事实

#### 6.14.3 通用错误模型

建议第一批 Tool 至少统一以下错误码：

- `INVALID_ARGUMENT`
- `NOT_FOUND`
- `PERMISSION_DENIED`
- `RATE_LIMITED`
- `UPSTREAM_UNAVAILABLE`
- `PARTIAL_DATA`
- `CONFLICT`
- `RETRY_LATER`

错误响应建议包含：

- `code`
- `message`
- `retryable`
- `suggested_action`

其中 `suggested_action` 很重要，因为 Hermes 需要知道下一步是“缩小时间窗重试”“稍后重试”“改查缓存”，还是“请求人工确认”。

#### 6.14.4 写操作安全约束

PoC 阶段建议默认把大部分 Tool 设计为只读；少量写操作 Tool 应遵守以下规则：

- 默认先 `dry_run`，确认影响范围后再执行
- 必须记录 `reason`
- 必须返回变更前后摘要
- 不允许无审计地批量改主数据
- 解析规则修正默认只影响后续数据，不反写历史
- 如需重放历史数据，必须显式调用重放类能力，而不是隐式覆盖

这点很关键，因为你的场景里用户会不断修正误报、资产映射、解析规则；如果写操作没有边界，后续排查会非常混乱。

#### 6.14.5 资产域 Tool 合约

`asset.search`

- 输入：
  - `query`：IP、域名、主机名、系统名等单值查询
  - `indicators[]`：允许同时传多个标识
  - `limit`
  - `include_inactive`
- 输出：
  - 匹配到的 `asset` / `asset_endpoint` / `asset_alias`
  - `matched_on`：命中依据，如 `ip`、`hostname`、`domain`
  - `confidence`
  - `match_reason`

`asset.get`

- 输入：
  - `asset_id`
  - `include`：建议支持 `endpoints`、`aliases`、`recent_cases`、`related_alerts`
- 输出：
  - 资产台账信息
  - 端点与别名
  - 最近关联案件与告警摘要
  - 当前风险摘要

`asset.list`

- 输入：
  - `filters`：如 `system_name`、`owner_team`、`internet_exposed`、`risk_level`
  - `sort`
  - `limit`
  - `cursor`
- 输出：
  - 资产列表卡片
  - 翻页信息

`asset.propose-link`

- 输入：
  - `subject_type`：如 `endpoint`、`alias`
  - `subject_id`
  - `target_asset_id`
  - `reason`
  - `confidence`
  - `dry_run`
- 输出：
  - 候选归并建议
  - 影响范围摘要
  - 是否仅影响后续归并判断

这里建议继续保持“提出归并建议”而不是“直接合并资产”，避免 Agent 一次误判破坏主数据。

#### 6.14.6 告警与案件域 Tool 合约

`alert.fetch`

- 输入：
  - `time_range`
  - `source_ids`
  - `min_severity`
  - `status`
  - `limit`
  - `cursor`
- 输出：
  - 告警摘要列表
  - 每条告警的 `alert_id`、`case_id`、`attack_stage`
  - `suspected_noise_score`
  - `needs_intel_lookup`

`alert.detail`

- 输入：
  - `alert_id`
  - `include`：建议支持 `raw_refs`、`matched_rule`、`evidence`
- 输出：
  - 完整 `normalized_alert`
  - 原始事件引用
  - 当前解析规则版本
  - 证据摘要

`case.list`

- 输入：
  - `status`
  - `overall_severity`
  - `current_stage`
  - `sort`
  - `limit`
  - `cursor`
- 输出：
  - 案件列表卡片
  - 总体等级
  - 最近更新时间
  - 关键攻击者 / 目标系统摘要

`case.get`

- 输入：
  - `case_id`
  - `include`：建议支持 `targets`、`actor_summary`、`artifacts`、`score_summary`
- 输出：
  - 案件头部摘要
  - 目标系统摘要
  - 攻击者画像摘要
  - 当前阶段与总体等级

`case.timeline`

- 输入：
  - `case_id`
  - `time_range`
  - `include_evidence`
- 输出：
  - 已排序时间线
  - 每个节点的事件摘要、证据引用、评分影响
  - 同一时间线节点下的多条设备证据聚合结果

`case.update-status`

- 输入：
  - `case_id`
  - `target_status`
  - `reason`
  - `operator`
  - `dry_run`
- 输出：
  - 变更前状态
  - 变更后状态
  - 审计引用

`case.explain-link`

- 输入：
  - `case_id`
  - `target_type`：`alert` / `actor` / `artifact` / `asset`
  - `target_id`
- 输出：
  - 关联置信度
  - 关联因子列表
  - 支撑证据列表
  - 反向证据或不确定性说明

这个 Tool 很重要，因为它直接服务于“为什么我认为这些事件属于同一攻击链”。

#### 6.14.7 证据、画像与攻击产物域 Tool 合约

`evidence.list`

- 输入：
  - `case_id` 或 `alert_id`
  - `type`
  - `limit`
  - `cursor`
- 输出：
  - 证据摘要列表
  - `evidence_type`
  - `relevance_score`
  - `source_ref`

`evidence.get`

- 输入：
  - `evidence_id`
  - `include`：建议支持 `excerpt`、`raw_ref`、`related_alerts`
- 输出：
  - 证据详情
  - 证据摘录
  - 原始日志或截图引用
  - 与案件/告警的关联关系

`actor.get`

- 输入：
  - `actor_id`，或允许用 `case_id` 取当前主画像
  - `include`：建议支持 `indicators`、`linked_cases`
- 输出：
  - 攻击者画像摘要
  - 当前主要指标集合
  - 关联案件摘要
  - 当前画像置信度

`artifact.get`

- 输入：
  - `artifact_id`
- 输出：
  - 产物类型、位置、首次出现/最近出现时间
  - 关联资产、关联告警、关联案件
  - 当前风险说明

#### 6.14.8 情报域 Tool 合约

`intel.lookup`

- 输入：
  - `indicator`
  - `indicator_type`
  - `providers`
  - `use_cache`
  - `max_providers`
- 输出：
  - 聚合后的情报结论
  - 各情报源标签摘要
  - `cache_hit`
  - `ttl`
  - `confidence`

`intel.cache-get`

- 输入：
  - `indicator`
  - `indicator_type`
- 输出：
  - 已缓存的情报摘要
  - 最近查询时间
  - 过期状态
  - 可否直接复用

情报 Tool 不建议默认回传各平台的大段原始文本，而应优先输出归纳后的结构化摘要，必要时再附 `source_ref`。

#### 6.14.9 输出域 Tool 合约

`notify.preview`

- 输入：
  - `case_id`
  - `channel`
  - `template`
- 输出：
  - 通知标题
  - 通知正文
  - 触发原因摘要
  - 建议接收对象

`notify.send`

- 输入：
  - `case_id` 或 `preview_id`
  - `channel`
  - `reason`
  - `dry_run`
- 输出：
  - 发送状态
  - 投递记录引用
  - 失败原因或重试建议

`report.draft`

- 输入：
  - `case_id`
  - `template`
  - `tone`
  - `include_sections`
- 输出：
  - 报告草稿
  - 章节结构
  - 引用的案件、证据、情报对象

`report.export`

- 输入：
  - `report_id`
  - `format`
- 输出：
  - 导出结果
  - 文件引用
  - 导出时间

PoC 阶段建议先把导出格式控制在 `markdown`、`html` 两种，避免一开始就把文档排版做得过重。

#### 6.14.10 接入与解析域 Tool 合约

`source.list`

- 输入：
  - `status`
  - `source_type`
  - `limit`
  - `cursor`
- 输出：
  - 信源列表
  - 最近运行状态
  - 最近成功取数时间
  - 最近失败摘要

`source.run-history`

- 输入：
  - `source_id`
  - `time_range`
  - `limit`
- 输出：
  - 运行历史
  - 每次执行的开始/结束时间
  - 拉取记录数、标准化成功数、失败数
  - 失败原因

`upload.list`

- 输入：
  - `status`
  - `source_id`
  - `time_range`
  - `limit`
  - `cursor`
- 输出：
  - 上传任务列表
  - 文件名、来源、处理状态、处理结果摘要

`upload.status`

- 输入：
  - `upload_job_id`
- 输出：
  - 任务状态
  - 解析进度
  - 失败原因
  - 产出的 `raw_event` / `normalized_alert` 数量摘要

`parser.profile-get`

- 输入：
  - `profile_id` 或 `source_id`
  - `version`
- 输出：
  - 当前解析规则摘要
  - 样例字段映射摘要
  - 当前规则版本
  - 是否只影响后续数据
  - 是否支持历史重放

#### 6.14.11 Hermes 最小调用闭环

结合你当前的目标工作流，PoC 阶段建议先让 Hermes 稳定走通以下调用顺序：

1. `alert.fetch`：获取待研判的新告警摘要
2. `alert.detail`：查看关键告警详情
3. `asset.search` / `asset.get`：确认被打对象是谁
4. `case.get` / `case.timeline`：理解这是不是已有案件的一部分
5. `case.explain-link`：解释为何这些事件被归到一起
6. `intel.lookup`：仅在证据不足或攻击源需要补证时调用
7. `notify.preview`：当总体风险超过阈值时生成通知草稿
8. `report.draft`：在需要复盘或输出时生成报告草稿

也就是说，Hermes 的主要职责仍然是“读取摘要 -> 请求补证 -> 解释链路 -> 形成输出”，而不是“直接吞原始日志做海量计算”。

### 6.15 Hermes Spike 核心 Tool Schema（v0.1）

上一节定义的是“Tool 合约边界”，这一节进一步收敛到“Spike 第一批真正要实现的核心 Schema”。

目标不是把所有 Tool 一次做完，而是先把最关键的分析闭环跑通，并且保证这些 Schema 后续还能平滑演进到 MVP。

#### 6.15.1 Spike 纳入范围

建议第一轮 Hermes Spike 只实现以下 `9` 个 Tool：

- `alert.fetch`
- `alert.detail`
- `asset.search`
- `case.get`
- `case.timeline`
- `case.explain-link`
- `intel.lookup`
- `notify.preview`
- `report.draft`

这一组已经足够覆盖：

- 新告警进入待办队列
- Agent 理解单条告警
- Agent 识别被打资产
- Agent 理解案件上下文
- Agent 解释案件关联理由
- Agent 按需补充情报
- Agent 输出通知和报告草稿

#### 6.15.2 Spike 暂不纳入范围

以下 Tool 虽然重要，但不建议放进第一轮 Spike：

- `case.update-status`
- `asset.propose-link`
- `notify.send`
- `report.export`
- `source.run-history`
- `upload.status`
- `parser.profile-get`

原因不是这些能力不需要，而是它们更偏“运维、治理、输出落地、规则运营”，不应阻塞第一轮“能否稳定分析”的验证。

#### 6.15.3 `alert.fetch` Schema

用途：拉取待研判的告警摘要队列，供 Hermes 决定下一步要不要深入分析。

请求示例：

```json
{
  "time_range": {
    "from": "2026-04-13T00:00:00+08:00",
    "to": "2026-04-13T23:59:59+08:00",
    "timezone": "Asia/Shanghai"
  },
  "source_ids": ["src_waf_prod_01", "src_dpi_edge_02"],
  "min_severity": "medium",
  "status": ["new", "open"],
  "limit": 20,
  "cursor": null,
  "sort": {
    "by": "event_time",
    "order": "desc"
  }
}
```

响应 `data.alerts[]` 最小字段建议：

- `alert_id`
- `occurred_at`
- `source_id`
- `source_type`
- `title`
- `normalized_type`
- `attack_stage`
- `severity`
- `confidence`
- `suspected_noise_score`
- `actor_fingerprint`
- `target_asset_hint`
- `case_id`
- `needs_intel_lookup`
- `summary`

设计要点：

- 这里返回的是“待办摘要”，不是完整告警正文
- 必须给出 `suspected_noise_score`，便于 Hermes 初步跳过明显噪音
- `target_asset_hint` 可以只是资产名/IP，不要求一定已经完成精确归并

#### 6.15.4 `alert.detail` Schema

用途：当 Hermes 决定深入分析某条告警时，读取其完整标准化结果和关键证据引用。

请求示例：

```json
{
  "alert_id": "alt_01JXYZ9M3K4Q",
  "include": ["matched_rule", "evidence", "raw_refs"]
}
```

响应 `data.alert` 最小字段建议：

- `alert_id`
- `raw_event_id`
- `parser_profile_version_id`
- `occurred_at`
- `title`
- `normalized_type`
- `attack_stage`
- `severity`
- `confidence`
- `src_ip`
- `src_port`
- `dst_ip`
- `host`
- `url`
- `http_method`
- `matched_rule_name`
- `matched_rule_id`
- `asset_id`
- `target_endpoint_id`
- `actor_fingerprint`
- `evidence_summary`
- `case_id`

设计要点：

- `alert.detail` 返回的是“标准化后的准事实”，不是原始设备响应全文
- 原文通过 `raw_refs` 引用，不默认直接塞给 Hermes
- `parser_profile_version_id` 必须保留，方便回溯“当时是按哪条规则解析的”

#### 6.15.5 `asset.search` Schema

用途：根据 IP、域名、主机名、系统名等线索快速定位资产。

请求示例：

```json
{
  "query": "api.example.com",
  "indicators": ["203.0.113.12", "api-prod-01", "api.example.com"],
  "include_inactive": false,
  "limit": 10
}
```

响应 `data.candidates[]` 最小字段建议：

- `asset_id`
- `asset_name`
- `system_name`
- `asset_type`
- `matched_on`
- `matched_value`
- `confidence`
- `internet_exposed`
- `owner_team`
- `current_risk_level`

设计要点：

- 这个 Tool 不负责“最终裁决”，只负责给出候选和置信度
- 用户资产经常有别名、多 IP、多环境，这个 Tool 必须允许一查多结果

#### 6.15.6 `case.get` Schema

用途：读取案件头部摘要，用于回答“谁在打、打谁、现在处于什么阶段”。

请求示例：

```json
{
  "case_id": "case_01JXYZR7F2AB",
  "include": ["targets", "actor_summary", "artifacts", "score_summary"]
}
```

响应 `data.case` 最小字段建议：

- `case_id`
- `title`
- `status`
- `overall_severity`
- `current_stage`
- `first_seen_at`
- `last_seen_at`
- `primary_actor_id`
- `primary_actor_summary`
- `target_asset_count`
- `target_assets[]`
- `artifact_count`
- `score_current`
- `score_trend`
- `why_open`

设计要点：

- 这条 Tool 面向“案件首页信息”，要尽量短平快
- `why_open` 很关键，它是给 Hermes 和用户的共同解释入口

#### 6.15.7 `case.timeline` Schema

用途：展示攻击链过程，而不是简单平铺原始告警。

请求示例：

```json
{
  "case_id": "case_01JXYZR7F2AB",
  "time_range": {
    "from": "2026-04-10T00:00:00+08:00",
    "to": "2026-04-13T23:59:59+08:00",
    "timezone": "Asia/Shanghai"
  },
  "include_evidence": true
}
```

响应 `data.events[]` 最小字段建议：

- `timeline_event_id`
- `occurred_at`
- `stage`
- `title`
- `summary`
- `related_alert_ids`
- `related_evidence_ids`
- `actor_hint`
- `target_asset_ids`
- `score_delta`
- `confidence`

设计要点：

- 这里展示的是“归并后的时间线节点”，不是“每条日志一行”
- 必须允许把多个设备上的相关事件合并成一个时间线动作
- 这样才适合你说的“多时间、多 IP、多目标”的攻击链表达

#### 6.15.8 `case.explain-link` Schema

用途：解释为什么系统认为某条告警 / 某个 IP / 某个产物属于同一案件。

请求示例：

```json
{
  "case_id": "case_01JXYZR7F2AB",
  "target_type": "alert",
  "target_id": "alt_01JXYZ9M3K4Q"
}
```

响应 `data.link_decision` 最小字段建议：

- `is_linked`
- `confidence`
- `reason_summary`
- `positive_factors[]`
- `negative_factors[]`
- `uncertainties[]`
- `supporting_evidence_ids[]`

其中 `positive_factors[]` / `negative_factors[]` 每项建议包含：

- `factor_type`
- `weight`
- `summary`

推荐 `factor_type` 示例：

- `same_target_asset`
- `same_artifact`
- `same_attack_path`
- `same_payload_pattern`
- `same_time_cluster`
- `same_actor_fingerprint`
- `weak_signal_only`
- `conflicting_target`
- `insufficient_evidence`

设计要点：

- 这是整套系统“可解释性”的核心 Tool
- 它不是输出数学公式，而是输出人类可理解的关联理由

#### 6.15.9 `intel.lookup` Schema

用途：仅在需要补证时查询第三方情报，而不是对每条告警默认触发。

请求示例：

```json
{
  "indicator": "198.51.100.23",
  "indicator_type": "ip",
  "providers": ["vt", "xlab", "internal_ioc"],
  "use_cache": true,
  "max_providers": 3
}
```

响应 `data.result` 最小字段建议：

- `indicator`
- `indicator_type`
- `verdict`
- `confidence`
- `risk_tags[]`
- `provider_hits[]`
- `cache_hit`
- `ttl`
- `queried_at`

其中 `provider_hits[]` 每项建议包含：

- `provider`
- `verdict`
- `tags[]`
- `updated_at`

推荐 `verdict` 枚举：

- `malicious`
- `suspicious`
- `unknown`
- `benign`

设计要点：

- `intel.lookup` 的职责是“补强证据”，不是“替代研判”
- 即便情报是 `unknown`，案件也可能成立；不能把情报平台当唯一真相源

#### 6.15.10 `notify.preview` Schema

用途：在触发阈值达到时生成通知草稿，但不直接发送。

请求示例：

```json
{
  "case_id": "case_01JXYZR7F2AB",
  "channel": "feishu",
  "template": "high_risk_case_brief"
}
```

响应 `data.preview` 最小字段建议：

- `preview_id`
- `channel`
- `title`
- `body`
- `overall_severity`
- `why_now`
- `recommended_recipients[]`
- `dedupe_key`

设计要点：

- 预览和发送应明确拆开，避免 Agent 在 PoC 阶段误发通知
- `why_now` 是通知可信度的关键字段，必须说明“为什么现在提醒你”

#### 6.15.11 `report.draft` Schema

用途：生成案件报告草稿，辅助人工复核和对外输出。

请求示例：

```json
{
  "case_id": "case_01JXYZR7F2AB",
  "template": "incident_report_v1",
  "tone": "professional",
  "include_sections": [
    "summary",
    "timeline",
    "targets",
    "actor_profile",
    "evidence",
    "recommendations"
  ]
}
```

响应 `data.report` 最小字段建议：

- `report_id`
- `title`
- `summary`
- `outline[]`
- `draft_markdown`
- `referenced_case_ids[]`
- `referenced_evidence_ids[]`
- `referenced_intel_items[]`

设计要点：

- 第一轮先以 `markdown` 草稿为主，足够验证报告辅助能力
- 报告应优先复用案件、时间线、证据、情报的结构化结果，而不是重新自由发挥

#### 6.15.12 Spike 实施边界

为了防止第一轮 Spike 变成一个“伪完整平台”，建议加上以下硬边界：

- 不做自动发通知，只做 `notify.preview`
- 不做数据库全量 DDL，只先确定核心表结构与索引方向
- 不做所有设备适配，只先选 `1` 类 WAF 或 DPI 样例
- 不做自动修正规则写回，只先保留人工确认入口
- 不做多租户权限系统，只保留最小的读写边界设计

只要这轮 Spike 能证明：

- Hermes 能稳定消费这些 Tool
- Tool 返回结构足够稳定
- 核心分析闭环能跑通
- 输出能被用户理解并认可

那么就说明这一架构方向是可行的。

### 6.16 Hermes 运行时接线设计（v0）

前两节回答了“Tool 是什么”和“Tool 长什么样”。本节回答：

- Hermes 如何知道有哪些 Tool
- Hermes 如何知道自己该做什么
- Hermes 如何在巡检中形成稳定行为

#### 6.16.1 Hermes 接线所需四类对象

要让 Hermes 真正可运行，除了 Tool 本身，还需要至少四类接线对象：

1. `tool registry manifest`
2. `main analyst prompt`
3. `patrol loop config`
4. `memory policy`

没有这四类对象，Hermes 即使“理论上能调用 Tool”，也很难形成稳定、可控、可复盘的行为。

#### 6.16.2 Tool Registry Manifest

`tool registry manifest` 的作用是告诉 Hermes：

- 有哪些 Tool
- 每个 Tool 何时使用
- 每个 Tool 如何调用
- 每个 Tool 是否只读
- 每个 Tool 的成本与风险

建议维护一份**引擎无关的 canonical manifest**，其字段可先收敛为：

- `name`
- `description`
- `when_to_use[]`
- `input_contract_ref`
- `command_template`
- `read_only`
- `timeout_sec`
- `cost_level`
- `idempotent`

最小示意：

```json
{
  "tools": [
    {
      "name": "alert.fetch",
      "description": "拉取待研判告警摘要队列",
      "when_to_use": [
        "开始一轮巡检时",
        "需要获取最近的新告警时"
      ],
      "input_contract_ref": "spec:6.15.3",
      "command_template": "uv run python -m security_analyst_agent.cli alert.fetch --db-path ${SPIKE_DB_PATH} --payload '${JSON_PAYLOAD}'",
      "read_only": true,
      "timeout_sec": 15,
      "cost_level": "low",
      "idempotent": true
    }
  ]
}
```

设计建议：

- `command_template` 中允许使用环境变量占位符
- `when_to_use[]` 很重要，它直接帮助 Hermes 学会“何时调用”
- `read_only`、`timeout_sec`、`cost_level` 可作为后续调度和权限控制的依据

#### 6.16.3 Main Analyst Prompt

`main analyst prompt` 的作用不是重复产品介绍，而是给 Hermes 明确行为边界。

它至少应覆盖以下内容：

- 角色定位：蓝队分析 Agent
- 目标：发现真实攻击、补证、解释链路、形成输出
- 默认工作顺序：先查摘要，再查详情，再补证，再输出
- 禁止事项：不要直接处理海量原始日志，不要默认调用高成本情报，不要擅自发送通知
- 不确定性表达：证据不足时必须明确说明
- 输出风格：先结论，再依据，再不确定性

建议提示词骨架：

```markdown
你是一个蓝队安全分析 Agent。

你的主要职责：
1. 从告警摘要中识别值得研判的真实攻击线索
2. 通过案件、资产、证据、情报 Tool 补充上下文
3. 解释为什么若干事件属于同一攻击链
4. 在风险足够高时生成通知草稿或报告草稿

工作原则：
- 默认先用 `alert.fetch`
- 只有在需要确认上下文时再用 `alert.detail`
- 确认被攻击对象时优先用 `asset.search`
- 理解案件上下文时优先用 `case.get` 和 `case.timeline`
- 解释关联理由时优先用 `case.explain-link`
- 只在证据不足时调用 `intel.lookup`
- 只生成 `notify.preview`，不直接发送通知
- 不要直接处理海量原始日志
- 如果证据不足，必须明确写出不确定性
```

这份 Prompt 应尽量稳定，不建议把过多客户特定信息硬编码进去；客户特定上下文更适合通过记忆或运行时上下文注入。

#### 6.16.4 Patrol Loop Config

`patrol loop config` 的作用是告诉 Hermes：

- 何时启动一轮分析
- 每轮从哪里开始
- 什么时候停止
- 何时写入记忆

PoC 第一轮建议使用简单定时巡检，而不是事件驱动的复杂多阶段编排。

推荐最小结构：

- `schedule`
- `entry_tool`
- `default_filters`
- `max_alerts_per_run`
- `stop_conditions[]`
- `write_memory_on_finish`

最小示意：

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

一轮巡检的推荐步骤：

1. 调用 `alert.fetch`
2. 跳过明显噪音或低价值扫描
3. 对高价值对象调用 `alert.detail`
4. 调用 `asset.search`
5. 调用 `case.get` / `case.timeline`
6. 必要时调用 `case.explain-link`
7. 证据不足时调用 `intel.lookup`
8. 风险达到阈值时生成 `notify.preview`
9. 需要复盘时生成 `report.draft`
10. 写入本轮摘要记忆与检查点

#### 6.16.5 Memory Policy

Hermes 的记忆建议只保存**摘要型、可复用、非海量**的信息，而不是替代数据库。

建议写入记忆的内容：

- 最近巡检摘要
- 已打开案件的短摘要
- 攻击者画像的摘要变化
- 用户确认的误报 / 修正结论
- 最近一次巡检时间和 cursor / checkpoint

不建议写入记忆的内容：

- 原始日志全文
- 大量设备返回原文
- 全量告警明细
- 可从数据库稳定查询到的结构化事实

换句话说，记忆层应负责“帮助 Hermes 下次更快进入状态”，而不是“代替数据库存事实”。

#### 6.16.6 Hermes 如何知道要做什么

Hermes 的行为来源应明确拆成四层：

1. `Prompt`：告诉它角色与工作原则
2. `Tool Registry`：告诉它有哪些工具、何时用
3. `Patrol Loop`：告诉它何时开始、按什么顺序做
4. `Memory`：告诉它历史上有哪些重要上下文

也就是说，Hermes 不是“天然知道”如何研判，而是依赖这四层配置逐步形成稳定行为。

#### 6.16.7 PoC 第一轮的最小 Hermes 运行形态

PoC 第一轮建议只部署一个 `main analyst agent`，并配齐：

- 一份 `tool registry manifest`
- 一份 `main analyst prompt`
- 一份 `patrol loop config`
- 一份简化记忆策略

然后只跑以下场景：

- 手动触发一轮巡检
- 定时触发一轮巡检
- 对一个高风险案件生成通知草稿
- 对一个典型案件生成报告草稿

只要这个形态稳定，就足以证明 Hermes 能担任当前系统的编排和研判层。

## 7. 数据域与建议表

PoC 阶段建议至少维护以下数据域：

- `assets`
- `asset_aliases`
- `alerts`
- `raw_events`
- `cases`
- `case_evidence`
- `actor_entities`
- `attacker_profiles`
- `case_actor_links`
- `attack_artifacts`
- `case_artifact_links`
- `case_link_reasons`
- `intel_cache`
- `noise_rules`
- `notifications`
- `reports`
- `data_sources`
- `source_runs`
- `upload_jobs`
- `parser_profiles`
- `parser_profile_versions`
- `score_events`
- `feedback_entries`
- `correction_requests`
- `agent_decisions`

## 8. Token 与存储控制原则

- Agent 默认只读取摘要，不直接读取全量日志
- 原始日志入库存储，按需切片取证
- 工具必须支持分页、时间窗口、limit、cursor
- 重复低价值告警尽量做统计聚合，不反复传给 Agent
- 情报查询必须缓存
- 大部分“机械型判断”优先由确定性逻辑完成

## 9. 设备接入与告警标准化机制

不同安全设备的字段、导出格式和告警语义差异较大。PoC 不应让 Agent 对每条告警都现场理解字段，而应采用“样例驱动映射 -> 用户校准 -> 规则入库 -> 批量复用”的机制。

### 9.1 样例驱动映射

设备首次接入时，用户提供少量样例告警。样例可以来自：

- JSON
- CSV
- Excel
- HTML 表格导出
- 设备 API 返回片段

Agent 基于样例判断字段语义，并给出映射建议，例如：

- 哪个字段表示告警时间
- 哪个字段表示设备看到的源 IP
- 哪个字段表示 Header 中声明的客户端 IP
- 哪个字段表示目标 IP、域名、URL 或资产标识
- 哪个字段表示规则名、规则 ID、严重性、设备动作
- 哪些字段可以作为原始证据或证据摘要
- 哪些字段不确定，需要用户确认

### 9.2 用户校准

用户确认或修正 Agent 的字段理解结果，包括：

- 字段映射是否正确
- 某些字段是否应忽略
- 某些字段是否需要组合解析
- 某些字段是否存在设备特有含义
- 某些字段是否误导性较强

用户校准后的结果进入解析规则，而不是只保存在对话上下文中。

### 9.3 解析规则入库

确认后的映射应保存为设备解析画像，建议至少包含：

- `parser_profile_id`
- `device_type`
- `vendor`
- `product`
- `version`
- `input_format`
- `field_mapping`
- `normalization_rules`
- `created_from_samples`
- `approved_by_user`
- `status`

后续该设备的大量告警直接使用解析规则转换为标准告警模型，不再逐条调用 Agent 理解字段。

### 9.4 解析规则版本化

解析规则必须支持版本化。原因包括：

- 设备升级导致字段变化
- 导出格式变化
- 策略调整导致字段语义变化
- 用户发现历史映射存在错误
- 新样例暴露出之前未覆盖的字段情况

建议维护：

- `parser_profile`
- `parser_profile_version`
- `parser_test_sample`
- `parser_validation_result`

### 9.5 修改规则的影响范围

如果用户发现某个映射有误，可以要求 Agent 修改解析规则。修改时应遵守以下原则：

- 生成新的解析规则版本
- 新版本只影响后续数据转换
- 已入库的历史标准告警默认不自动重写
- 如果需要修正历史数据，必须作为单独的显式重放任务执行
- 历史数据应保留当时使用的解析规则版本，确保审计可追溯

该原则可以避免用户修正规则时破坏既有案件、历史通知和报告证据链。

### 9.6 Agent 介入时机

Agent 只在以下情况下介入解析规则相关工作：

- 新设备首次接入
- 新格式首次出现
- 解析失败率升高
- 关键字段缺失
- 用户要求修正规则
- 新样例与现有规则明显不一致

批量转换应由确定性解析器完成，避免不必要的 token 消耗。

### 9.7 原始告警到 `normalized_alert` 的转换流水线

当前方案不建议让 Agent 对每条原始告警做实时理解，而应采用“规则优先、Agent 兜底”的标准化流水线。

建议流程如下：

1. **接收输入**
   - 输入可来自：
     - `data_source` 触发的 `source_run`
     - 用户提交的 `upload_job`
   - 系统先记录输入来源、时间、设备类型、接入方式

2. **落原始事件**
   - 原始告警先保存为 `raw_event`
   - 原文不直接丢弃，后续解析、复盘、重放都依赖它

3. **选择解析规则**
   - 根据 `source_id`、设备类型、厂商、格式，选择对应的 `parser_profile_version`
   - 若找不到规则，则进入：
     - `待映射`
     - `待校准`
     - 或触发 Agent 辅助理解样例

4. **字段抽取**
   - 解析器按规则从原始输入中抽取候选字段，例如：
     - 时间
     - 源 IP
     - 客户端 IP
     - 目标 IP / 域名 / URL
     - 规则 ID / 规则名
     - 严重性
     - 动作
     - 请求路径
     - 原始证据片段

5. **标准化映射**
   - 将厂商字段映射为系统内部标准字段
   - 同时完成：
     - 时间格式统一
     - IP/域名规范化
     - 枚举值映射
     - `alert_type` 映射
     - `attack_stage` 映射
     - `attack_surface` 映射

6. **增强与补充**
   - 在标准化基础上做确定性增强：
     - 资产映射到 `asset_id`
     - 入口点映射到 `target_endpoint_id`
     - 生成 `actor_fingerprint`
     - 提取 `matched_features`
     - 生成 `evidence_summary`

7. **校验与分诊**
   - 校验必填字段是否具备
   - 若缺失关键字段：
     - 允许生成部分 `normalized_alert`
     - 但应标记 `triage_status`
     - 或进入 `needs_review`
   - 若完全无法理解，则保留 `raw_event`，不强制生成错误的 `normalized_alert`

8. **关联与落库**
   - 成功标准化后写入 `normalized_alert`
   - 后续再进入：
     - 去重
     - 噪音判断
     - 案件归并
     - 证据切片生成

### 9.8 转换原则

原始告警转换成 `normalized_alert` 时应遵守以下原则：

- 一条原始告警最多生成一条主 `normalized_alert`
- 允许存在部分字段为空，但不允许编造字段
- 无法解释的字段保留在原始层，不强行塞入标准层
- 规则驱动是主路径，Agent 只在异常或新样本时介入
- 每条 `normalized_alert` 都应能追溯到：
  - `raw_event`
  - `parser_profile_version`
  - `source_id` 或 `upload_job`

### 9.9 转换失败与回退策略

当标准化失败时，建议区分以下几种情况：

- **规则缺失**
  - 设备首次接入或格式首次出现
  - 进入样例映射流程

- **规则过期**
  - 设备字段变化，旧规则不再适用
  - 生成新规则版本

- **关键字段缺失**
  - 可以部分生成 `normalized_alert`
  - 但标记为 `needs_review`

- **完全不可解析**
  - 只保留 `raw_event`
  - 记录失败原因
  - 等待用户补样例或 Agent 重新理解

### 9.10 WAF 示例

以一条 WAF 原始告警为例，转换过程可理解为：

- 原始字段：
  - `attack_ip`
  - `host`
  - `uri`
  - `risk_level`
  - `rule_name`
  - `action`

- 转换后：
  - `observed_source_ip`
  - `target_endpoint_id`
  - `alert_type`
  - `attack_stage`
  - `severity`
  - `device_action`
  - `rule_name`
  - `evidence_summary`

其中：

- `host + uri` 可共同帮助映射 `asset_id` 和 `target_endpoint_id`
- `rule_name` 和请求特征可共同帮助映射 `alert_type`
- `action` 统一映射为 `allowed` / `blocked` / `observed`

## 10. PoC / MVP 验证思路

PoC 阶段不追求“全自动准确判断一切”，而是验证该架构是否能有效把海量告警收敛成少量可研判案件，并给出有证据的攻击链还原结果。

### 10.1 建议验证场景

优先选择用户已知答案或可人工复盘的样本，例如：

- 单纯扫描但未成功利用
- 低价值高频误报规则
- 漏洞利用后上传 WebShell
- WebShell 控制后执行命令和内网扫描
- 同一攻击活动跨多天、多 IP、多设备出现

### 10.2 最小验证闭环

PoC 至少应验证以下链条：

`资产入库 -> 样例告警解析 -> 设备接入或文件上传 -> 批量标准化 -> 告警聚合 -> 案件生成 -> 按需情报补证 -> 通知草稿 -> 报告草稿`

### 10.3 关键评估指标

建议至少观察以下指标：

- 告警压缩率：多少原始告警被收敛成多少案件
- 噪音过滤可解释性：每条被降噪事件是否能说明原因
- 真实攻击召回：人工认为重要的攻击是否被系统捕获
- 攻击链完整度：是否能把跨天、多 IP、多阶段事件串起来
- 通知可用性：通知内容是否足以指导下一步排查
- 报告可用性：报告草稿是否可直接作为人工撰写底稿

### 10.4 失败判据

若出现以下情况，说明方案还不能进入实现阶段：

- 资产归并大量错误，导致案件挂错目标
- 同类设备告警难以稳定标准化
- 案件过度碎片化，无法表达同一次攻击活动
- 案件过度合并，把无关噪音揉成一案
- 无法给出可审计的关联理由

## 11. 前端策略

PoC 阶段不强依赖前端，优先验证工作流。

如需演示，可增加极简前端，并优先围绕以下 MVP 页面展开：

- `案件列表页`
- `案件详情页`
- `资产清单页`
- `资产详情页`
- `通知页`
- `报告页`
- `接入中心`

不建议在 PoC 阶段构建完整 SOC 平台式前端。

### 11.1 案件详情页 MVP 结构

用户确认后的案件详情页采用三屏式低复杂度结构，目标不是承载所有操作，而是让用户快速理解一个案件：

- 谁在攻击
- 攻击谁
- 干了什么
- Agent 为什么这样判断
- 如有需要，用户如何修正

页面结构如下：

- 第一屏：`攻击画像` ｜ `目标系统`
- 第二屏：`攻击过程（含证据）` ｜ `总体等级 + 评分记录`
- 第三屏：`用户反馈与修正`

### 11.2 第一屏：攻击画像与目标系统

第一屏只回答两个最关键的问题：

- 谁在攻击
- 攻击谁

`攻击画像` 模块建议展示：

- 画像标识
- 关联来源线索（如多个 IP）
- 关键行为特征
- 关联强度

`目标系统` 模块建议展示：

- 核心受害系统
- 关联探测系统
- 影响范围说明

这里不建议放长段解释，也不建议把评分细节堆在这一屏。

### 11.3 第二屏：攻击过程与总体等级

第二屏回答：

- 攻击者做了什么
- Agent 为什么认为这是一条成立的攻击链

`攻击过程` 模块应以时间顺序展示关键阶段，每个阶段只挂 1 条或少量关键证据，避免证据堆积。推荐阶段包括：

- 侦察
- 利用
- 控制 / 持久化
- 横向准备 / 后渗透

`总体等级 + 评分记录` 模块建议展示：

- 当前总体等级（如观察、可疑、高风险、紧急）
- 最近升分/降分记录
- 一个“查看评分依据”的入口

默认不展示复杂细分评分，细节放在下钻层中查看。这样更符合用户直觉，也避免制造虚假的精确感。

### 11.4 第三屏：用户反馈与修正

反馈不是案件详情页的主任务，因此应放在第三屏或折叠区域，避免干扰主信息阅读。

用户在这里可以：

- 修正攻击者关联
- 修正目标系统范围
- 修正攻击过程归因
- 补充备注或新证据

反馈入口应轻量，不建议默认展示复杂的审核流程，也不建议放大量操作按钮。

### 11.5 页面阅读逻辑

案件详情页的推荐阅读顺序是：

1. 先看 `攻击画像` 和 `目标系统`
2. 再看 `攻击过程` 和 `总体等级`
3. 最后按需进入 `反馈与修正`

该顺序的核心目的，是让页面像“安全专家在给用户讲案子”，而不是像“一个需要立刻操作的控制台”。

### 11.6 案件列表页 MVP 结构

案件列表页在 MVP 中定位为“待办队列”，核心目标不是展示所有态势，而是帮助用户快速判断：

- 现在最该处理哪几个案件
- 哪些案件等级最高
- 哪些案件刚刚发生风险变化

因此，案件列表页推荐采用“优先级队列”而不是复杂泳道或重型 Dashboard。

建议行为如下：

- 默认按 `总体等级` 和 `最近变化` 排序
- 支持按状态、目标系统、时间范围、等级等条件筛选
- 列表保持简单，不展示过多字段

每条案件在列表中建议至少展示：

- `总体等级`
- `攻击画像`
- `目标系统`
- `当前阶段 / 做了什么`
- `最近活动时间`

不建议在列表页直接展示复杂评分细节、长时间线或大量证据。列表页的职责只是“排队”和“引导进入详情页”。

### 11.7 资产模块 MVP 结构

资产模块在 MVP 中建议拆成两个层级：

- `资产清单页`
- `资产详情页`

其关系应与案件模块保持一致：

- `案件列表页 -> 案件详情页`
- `资产清单页 -> 资产详情页`

这样用户既可以从全局资产台账进入，也可以从案件中跳转到具体资产。

### 11.8 资产清单页

资产清单页采用“双视角”设计，但共享同一份资产数据：

- `视角 A：资产台账`
- `视角 B：风险视角`

用户确认的默认行为是：

- 默认展示 `顶部操作区 + 视角 A（资产台账）`
- 通过 Tab 切换到 `视角 B（风险视角）`

顶部操作区建议包含：

- 搜索
- 业务筛选
- 环境筛选
- 风险等级筛选
- 负责人筛选

`视角 A：资产台账` 主要用于：

- 查看资产名称、业务归属、负责人、环境
- 从 IP、域名、主机名、别名反查系统
- 理解资产身份与归属

`视角 B：风险视角` 主要用于：

- 查看最近最危险的资产
- 关联最近案件和最近攻击活动
- 支持值守时快速扫重点资产

不建议把资产清单页做成复杂的总览 Dashboard。它的职责是“查资产”和“找风险资产”。

### 11.9 资产详情页

资产详情页采用“资产台账 + 身份归并”融合方式。

页面目标是同时回答：

- 这个系统是谁
- 它在不同设备里叫什么
- 它暴露了什么
- 最近出了什么安全问题

建议结构如下：

- 第一屏：`资产台账` ｜ `身份归并`
- 第二屏：`资产暴露面` ｜ `最近安全状态`
- 第三屏：`关联案件` ｜ `修正入口`

其中：

`资产台账` 模块建议展示：

- 资产名称
- 业务归属
- 负责人
- 环境

`身份归并` 模块建议展示：

- 公网 IP
- 内网 IP
- 域名
- 主机名
- 其他别名
- 归并说明

`最近安全状态` 模块建议展示：

- 当前风险
- 最近案件数
- 最近一次攻击时间
- 简短状态说明

`修正入口` 模块仅作为轻量入口，用于：

- 修正资产别名归并
- 新增入口点
- 修正负责人或业务归属

不建议把资产详情页做成纯技术管理页或纯风险页，而应保持“身份 + 风险”并重。

### 11.10 通知页

通知功能在 MVP 中建议作为独立页面，而不是与报告页强行合并。

通知页的核心职责是：

- 配置通知方式
- 查看已通知事件
- 回溯通知发送状态

建议结构如下：

- 第一屏：`通知配置`
- 第二屏：`已通知事件列表 + 筛选`

`通知配置` 模块建议包含：

- 通知通道配置（如告警平台 API、飞书 Webhook、邮件）
- 默认通知模板
- 默认发送策略

`已通知事件列表` 模块建议支持：

- 按时间筛选
- 按等级筛选
- 按发送状态筛选
- 按通知通道筛选
- 按案件号搜索

通知页的目标是“发出去”和“看发送记录”，不建议在这里承载复杂案件分析内容。

### 11.11 报告页

报告功能在 MVP 中建议作为独立页面，核心职责是：

- 围绕案件生成报告
- 管理报告模板与导出格式
- 查看历史报告列表

建议结构如下：

- 第一屏：`报告关联案件 + 配置 + 编写`
- 第二屏：`报告列表`

`报告关联案件 + 配置 + 编写` 模块建议包含：

- 当前关联案件
- 关联资产
- 报告模板
- 输出格式
- 草稿生成入口
- 编辑入口

`报告列表` 模块建议展示：

- 关联案件
- 报告标题
- 当前状态（草稿 / 已导出）
- 导出格式

报告页的目标是“写出来”和“导出来”，不建议在这里承载通知通道配置。

### 11.12 输出页面职责边界

通知页与报告页虽然都属于“事件输出”，但职责应明确分开：

- `通知页` 负责事件推送与发送记录
- `报告页` 负责内容产出与报告沉淀

这种拆分更适合后续扩展，也能避免一个页面同时承担“运营发送”和“内容编辑”两种完全不同的任务。

### 11.13 接入中心

用户确认后，MVP 还应补充一个独立的 `接入中心` 页面，用于统一管理：

- 用户手工上传
- Agent 通过 CLI / API 持续取数
- 信源运行状态

接入中心不应与案件、资产、通知、报告页混在一起，因为它属于系统接入与运维心智，而不是日常研判心智。

### 11.14 接入中心页面结构

接入中心采用“上面配置、下面状态”的布局：

- 上半区：配置区
- 下半区：信源运行状态

其中，上半区通过 Tab 切换三种接入方式：

- `CLI 配置`
- `API 配置`
- `手动上传`

下半区统一展示所有信源或上传任务的运行状态，而不是按接入方式拆散。

### 11.15 顶部配置区

顶部配置区的核心目标是让用户决定“怎么接入数据”，而不是查看复杂运行日志。

`CLI 配置` 应支持：

- 数据源名称
- 命令路径
- 拉取频率
- 解析规则
- 启用状态

`API 配置` 应支持：

- 接口地址
- 鉴权方式
- 轮询频率
- 解析规则
- 启用状态

`手动上传` 应支持：

- 上传资产清单
- 上传告警文件
- 上传日志文件
- 上传样例告警

手动上传主要用于：

- PoC 阶段
- 离线研判
- 补充样本
- 解析规则训练

### 11.16 底部运行状态区

底部运行状态区统一展示各类信源当前状态，不区分其来自 CLI、API 还是上传任务。

每个信源或任务建议展示：

- 数据源名称
- 接入方式
- 当前状态
- 最近拉取或处理结果
- 最近成功/失败时间
- 当前解析规则版本

该区域应支持按以下条件筛选：

- 数据源名称
- 接入方式
- 状态
- 最近失败
- 解析规则

这样用户可以快速回答：

- 哪个信源正在正常工作
- 哪个信源最近异常
- 哪个上传任务还在等待处理
- 哪个解析规则正在生效

### 11.17 接入中心职责边界

接入中心的职责是：

- 配置接入方式
- 查看信源状态
- 管理上传任务
- 管理解析规则入口

不建议在接入中心直接承载案件分析、通知发送或报告编写功能。

## 12. 目标态工作流（用户确认）

以下流程代表用户当前希望最终实现的业务闭环。PoC 阶段不要求一次性全部做完，但后续设计和实现应尽量围绕这条主流程演进。

### 12.1 资产导入与维护

1. 用户先收集客户资产清单
2. Agent 从资产文件中提取并结构化存储到数据库
3. 后续若用户调整资产，Agent 应通过对应 Tool 更新资产数据
4. 若 Agent 在研判过程中发现资产存在新增标识、别名或疑似归并关系，应先生成候选更新，再由人工确认

该流程的目标是让 Agent 始终掌握尽可能准确的资产现状，并为后续告警归并和案件研判提供底座。

### 12.2 设备接入与告警获取/导入

1. 将各类安全产品的 Web 管理接口封装为 CLI 或 API 接入能力
2. 同时保留手工上传入口，用于导入资产清单、设备导出告警、日志文件和样例告警
3. 通过 Skill 向 Agent 解释工具能力、适用场景、字段含义与限制
4. Agent 使用对应 Tool 获取设备告警、详情或相关日志；手工上传的数据也进入同一标准化流程
5. 在设计时需要持续平衡 token 消耗和数据库存储压力

该流程的关键不是“让 Agent 直接理解每个设备页面”，而是通过稳定的 CLI 输出和 Skill 约束，使 Agent 能按需获取信息、避免高成本滥查。

### 12.3 告警评估与历史结合

1. Agent 维护资产被攻击情况数据库
2. Agent 查询到新告警后，先对当前告警进行初步评估
3. 再结合数据库中的历史记录、相似案件、历史攻击轨迹和资产背景进行综合判断

该流程要求 Agent 具备长期记忆，不只看当前一条告警，而是要识别长期打点、持续探测和多阶段攻击。

### 12.4 攻击 IP 补证

1. 如果 Agent 认为需要进一步分析攻击 IP
2. 则调用对应 Tool 查询第三方情报、IOC、历史命中情况或其他补充证据
3. 将查询结果回填到当前案件或攻击实体记录中

该流程强调“按需补证”而不是“逢 IP 必查”，以控制 token、API 配额和查询成本。

### 12.5 攻击地址动态加权

用户希望对攻击地址做动态加权或降权，例如：

- 一开始基于高危特征判断某地址风险较高
- 若后续仅出现低价值扫描并长时间沉默，则风险下降
- 若后续调查发现部分特征不足以证明真实攻击，则需要降低风险判断
- 若持续命中多个资产、多个设备或出现成功利用迹象，则风险上升

但该机制不能设计得过于简单，不能只依赖单一总分。更适合拆分为以下多个维度：

- 攻击地址本身风险
- 当前案件置信度
- 目标资产重要性
- 活动新鲜度与持续性

### 12.6 高风险事件通知

1. 如果经过综合调查后，某个攻击地址对应的案件风险较高
2. Agent 应调用告警 Tool 向用户发送通知
3. 通知中需要包含攻击对象、攻击动作摘要、关键证据、当前判断和建议

这里的通知触发条件应以“综合风险”定义，而不是单独依赖 IP 风险值。

### 12.7 目标态总结

从业务角度看，用户期望的最终闭环可以概括为：

`资产入库 -> 设备取数 -> 告警评估 -> 历史关联 -> 按需情报补证 -> 动态风险更新 -> 高风险通知 -> 报告输出`

后续所有模型细化都应尽量服务于这条主流程。

## 13. 后续待细化主题

当前方案已经补充了第一版最小数据模型，但仍需继续细化以下内容：

1. `case` 状态机与升级/降级条件
2. `attacker_profile` 与 `case_actor_link` 的置信度规则
3. `parser_profile` 的规则 DSL 与版本重放机制
4. 风险评估公式、阈值与可视化方式
5. 误报沉淀与学习机制
6. 情报查询策略、缓存失效与成本控制
7. Tool 的权限边界、幂等策略与审计日志
8. 通知模板与发送策略
9. 报告模板、导出格式与引用规范
10. 多租户 / 多客户隔离边界

## 14. 建议的下一步

当前 `normalized_alert`、案件域、接入域、第一批 Tool 合约，以及 Hermes Spike 核心 Tool Schema 已经形成 v0 骨架。下一步建议按以下顺序推进：

1. 把 `6.15` 中的 `9` 个 Tool 收敛成 API schema / CLI contract
2. 写 `Hermes Spike` 的实现计划，明确哪些能力由 Hermes 负责、哪些由确定性组件负责
3. 细化 `case` 状态机、评分阈值与通知触发条件
4. 将 `asset / normalized_alert / case / data_source` 映射成数据库 schema 与 API schema
5. 选 `1` 类真实安全设备样例，验证 `parser_profile` 的样例驱动映射与版本修正规则

在上述五项完成前，不建议直接进入大规模实现阶段。

## 15. 最小数据模型（v0）

本节用于给 MVP 提供第一版可落地的数据建模骨架。当前目标不是直接产出数据库 DDL，而是先明确：

- 系统内部有哪些核心实体
- 这些实体之间如何关联
- 哪些字段是 MVP 必须具备的最小集合

### 15.1 建模原则

- 一个实体只表达一种核心业务含义，不混合职责
- 优先支持“案件化研判”，而不是“原始日志堆积”
- 默认保留原始证据引用，避免统一模型丢失可追溯性
- 用户修正、规则版本和评分变化都必须可审计
- MVP 先满足页面与工作流所需字段，不追求一次建全

### 15.2 关系总览

第一版核心关系如下：

- `asset` 聚合多个 `asset_endpoint` 和 `asset_alias`
- `normalized_alert` 由 `raw_event` 标准化而来，并可归入 `case`
- `case` 关联多个 `evidence_item`、`timeline_event`、`asset`
- `case` 通过 `case_actor_link` 关联 `attacker_profile`
- `case` 通过 `case_artifact_link` 关联 `attack_artifact`
- `data_source`、`upload_job`、`parser_profile` 支撑接入与标准化
- `notification` 和 `report` 作为案件输出物存在

### 15.3 资产域

#### `asset`

表示一个业务系统或应用服务，而不是单个 IP。

建议最小字段：

- `asset_id`
- `asset_name`
- `business_system`
- `asset_type`
- `criticality`
- `environment`
- `owner_team`
- `owner_contact`
- `status`
- `created_at`
- `updated_at`

#### `asset_endpoint`

表示该资产的入口点或可见标识。

建议最小字段：

- `endpoint_id`
- `asset_id`
- `endpoint_type`（如 `public_ip`、`internal_ip`、`domain`、`url`、`app_id`）
- `endpoint_value`
- `is_primary`
- `first_seen_at`
- `last_seen_at`

#### `asset_alias`

表示资产在不同设备或上下文中的别名。

建议最小字段：

- `alias_id`
- `asset_id`
- `alias_type`
- `alias_value`
- `source`
- `confidence`
- `is_active`

#### `asset_merge_candidate`

表示 Agent 发现的归并候选，不直接改动主数据。

建议最小字段：

- `candidate_id`
- `left_ref`
- `right_ref`
- `candidate_type`
- `reason`
- `confidence`
- `status`
- `created_at`

### 15.4 告警与证据域

#### `raw_event`

保存原始输入，用于审计和重新解析。

建议最小字段：

- `raw_event_id`
- `source_kind`（如 `cli`、`api`、`upload`）
- `source_ref`
- `payload_ref`
- `content_hash`
- `ingested_at`

#### `normalized_alert`

表示系统内部统一使用的标准化告警。

建议最小字段：

- `alert_id`
- `raw_event_id`
- `parser_profile_version_id`
- `source_id`
- `source_device_type`
- `observed_at`
- `ingested_at`
- `asset_id`
- `target_endpoint_id`
- `observed_source_ip`
- `claimed_client_ip`
- `actor_fingerprint`
- `alert_type`
- `attack_stage`
- `attack_surface`
- `severity`
- `device_action`
- `rule_id`
- `rule_name`
- `matched_features`
- `evidence_summary`
- `triage_status`
- `case_id`（可为空）

##### 15.4.1 `normalized_alert` 字段分组

为便于实现与后续扩展，建议将 `normalized_alert` 拆成以下字段组：

- 来源组：这条告警来自哪里
- 时间组：这条告警是什么时候被观察和入库的
- 目标组：这条告警打到了哪个资产或入口点
- 源身份组：设备看到的源是谁，以及有哪些客户端身份线索
- 攻击语义组：系统如何理解这条告警
- 检测依据组：设备是基于什么规则或特征命中的
- 证据组：给 Agent 和用户看的摘要证据
- 关联组：这条告警目前被如何分诊和归并

##### 15.4.2 `normalized_alert` MVP 必填字段

以下字段建议作为 MVP 必填项；如果设备无法提供原始含义，也应以 `null` 明确表示缺失，而不是省略字段。

- `alert_id`
- `raw_event_id`
- `parser_profile_version_id`
- `source_id`
- `source_device_type`
- `observed_at`
- `ingested_at`
- `alert_type`
- `attack_stage`
- `attack_surface`
- `severity`
- `device_action`
- `triage_status`

##### 15.4.3 `normalized_alert` MVP 强建议字段

以下字段虽然允许为空，但对案件化和后续研判价值很高，建议优先支持：

- `asset_id`
- `target_endpoint_id`
- `observed_source_ip`
- `claimed_client_ip`
- `actor_fingerprint`
- `rule_id`
- `rule_name`
- `matched_features`
- `evidence_summary`
- `case_id`

##### 15.4.4 字段语义说明

建议对以下关键字段做统一解释：

- `source_device_type`
  - 设备类别，如 `waf`、`dpi`、`edr`、`siem`

- `observed_at`
  - 设备实际观察到事件发生的时间

- `ingested_at`
  - 系统成功接收并入库该事件的时间

- `asset_id`
  - 这条告警当前映射到的业务资产 ID；映射失败时允许为空

- `target_endpoint_id`
  - 具体命中的入口点，如公网 IP、域名、URL 入口

- `observed_source_ip`
  - 设备实际看到的源 IP，不保证是真实客户端

- `claimed_client_ip`
  - Header、代理链或设备字段中声明的客户端 IP，不保证可信

- `actor_fingerprint`
  - 用于帮助归并攻击实体的行为或身份指纹，可由多个字段组合生成

- `alert_type`
  - 标准化后的攻击类型，如 `dir_scan`、`sql_injection_probe`、`rce_exploit`、`webshell_access`

- `attack_stage`
  - 攻击阶段，如 `recon`、`exploit`、`persistence`、`command_execution`、`lateral_prep`

- `attack_surface`
  - 攻击面，如 `web`、`network`、`host`、`account`、`api`

- `severity`
  - 设备告警强度的标准化结果，不等于最终案件风险等级

- `device_action`
  - 设备对该请求或事件采取的动作，如 `allowed`、`blocked`、`observed`

- `matched_features`
  - 命中的特征摘要，建议为短数组，不直接塞入整段原始内容

- `evidence_summary`
  - 供 Agent 或前端直接展示的一段简要证据说明

- `triage_status`
  - 当前分诊状态，如 `new`、`deduped`、`noise_candidate`、`case_linked`

##### 15.4.5 推荐枚举

以下枚举可作为第一版建议值域：

- `source_device_type`
  - `waf`
  - `dpi`
  - `edr`
  - `siem`
  - `host_audit`

- `attack_stage`
  - `recon`
  - `probe`
  - `exploit`
  - `persistence`
  - `command_execution`
  - `lateral_prep`
  - `unknown`

- `attack_surface`
  - `web`
  - `network`
  - `host`
  - `account`
  - `api`
  - `unknown`

- `severity`
  - `low`
  - `medium`
  - `high`
  - `critical`

- `device_action`
  - `allowed`
  - `blocked`
  - `observed`
  - `unknown`

- `triage_status`
  - `new`
  - `deduped`
  - `noise_candidate`
  - `needs_review`
  - `case_linked`

##### 15.4.6 最小 JSON 示例

以下示例仅表达字段结构，不代表最终数据库或 API 返回的精确格式：

```json
{
  "alert_id": "alt_20260413_0001",
  "raw_event_id": "raw_20260413_0001",
  "parser_profile_version_id": "ppv_waf_vendor_a_v12",
  "source_id": "src_waf_01",
  "source_device_type": "waf",
  "observed_at": "2026-04-12T09:37:11+08:00",
  "ingested_at": "2026-04-13T10:00:05+08:00",
  "asset_id": "asset_sys_a",
  "target_endpoint_id": "ep_app_example_com",
  "observed_source_ip": "8.8.8.8",
  "claimed_client_ip": null,
  "actor_fingerprint": "fp:webshell-uri:/shell.jsp",
  "alert_type": "webshell_access",
  "attack_stage": "command_execution",
  "attack_surface": "web",
  "severity": "high",
  "device_action": "observed",
  "rule_id": "waf-rule-2210",
  "rule_name": "WebShell Access",
  "matched_features": [
    "same_webshell_uri",
    "cmd_parameter_detected"
  ],
  "evidence_summary": "访问已落地的 WebShell URI，并携带命令执行特征参数",
  "triage_status": "case_linked",
  "case_id": "case_0007"
}
```

#### `evidence_item`

表示可直接支撑判断的证据切片。

建议最小字段：

- `evidence_id`
- `case_id`
- `evidence_type`
- `summary`
- `raw_ref`
- `source_alert_id`
- `captured_at`
- `confidence`

### 15.5 案件与画像域

#### `case`

表示一条攻击活动主线，是系统研判的核心对象。

建议最小字段：

- `case_id`
- `title`
- `status`
- `overall_severity`
- `case_confidence`
- `current_stage`
- `summary_current`
- `first_seen_at`
- `last_seen_at`
- `primary_asset_id`
- `notification_status`
- `report_status`
- `created_at`
- `updated_at`

#### `case_target_asset`

表示案件涉及哪些资产，以及这些资产在案件中的角色。

建议最小字段：

- `case_id`
- `asset_id`
- `role`（如 `primary_target`、`related_target`、`compromised`、`scanned`）
- `confidence`

#### `timeline_event`

表示案件中的关键时间线节点。

建议最小字段：

- `timeline_event_id`
- `case_id`
- `event_time`
- `stage`
- `summary`
- `source_refs`
- `evidence_refs`
- `is_key_milestone`

#### `attacker_profile`

表示可跨案件复用的攻击者画像或攻击活动画像。

建议最小字段：

- `attacker_profile_id`
- `label`
- `status`
- `confidence`
- `summary`
- `behavior_tags`
- `infrastructure_tags`
- `latest_activity_at`
- `created_at`
- `updated_at`

#### `case_actor_link`

表示某个案件与某个画像之间的关联关系。

建议最小字段：

- `case_id`
- `attacker_profile_id`
- `link_type`
- `link_confidence`
- `link_reason`
- `evidence_refs`
- `is_primary`

#### `attack_artifact`

表示能串联攻击链的产物。

建议最小字段：

- `artifact_id`
- `artifact_type`
- `artifact_value`
- `asset_id`
- `hash_value`
- `first_seen_at`
- `last_seen_at`
- `summary`

#### `case_artifact_link`

表示攻击产物与案件之间的关联。

建议最小字段：

- `case_id`
- `artifact_id`
- `role`
- `link_confidence`
- `link_reason`

#### `score_event`

表示案件评分变化的审计记录。

建议最小字段：

- `score_event_id`
- `case_id`
- `changed_at`
- `score_dimension`
- `delta`
- `reason_code`
- `reason_text`
- `evidence_refs`
- `trigger_source`

##### 15.5.1 `case` 字段语义说明

建议对以下字段做统一解释：

- `status`
  - 案件当前处理状态，表达案件生命周期

- `overall_severity`
  - 面向用户默认展示的总体等级，不等同于某条设备告警的 `severity`

- `case_confidence`
  - 当前案件是否为真实攻击活动的置信度

- `current_stage`
  - 当前攻击链走到的最高或最新阶段

- `summary_current`
  - 给用户看的当前案件摘要，建议保持简短

- `primary_asset_id`
  - 当前案件最核心的受害资产

- `notification_status`
  - 通知输出状态

- `report_status`
  - 报告输出状态

##### 15.5.2 推荐案件状态

第一版建议状态如下：

- `observing`
  - 观察中，证据不足或仍偏低价值

- `likely_noise`
  - 更像扫描噪音、失败探测或历史误报

- `suspicious`
  - 存在攻击迹象，但证据仍不完整

- `investigating`
  - 正在补证或等待更多证据

- `confirmed_attack`
  - 已有较强证据确认攻击成立

- `needs_review`
  - 机器判断不稳，需要人工复核

- `closed`
  - 已关闭或归档

##### 15.5.3 推荐总体等级

`overall_severity` 建议采用以下等级：

- `low`
- `watch`
- `suspicious`
- `high`
- `urgent`

用户界面中可映射为：

- 低风险
- 观察
- 可疑
- 高风险
- 紧急

##### 15.5.4 `current_stage` 推荐枚举

`current_stage` 建议与 `normalized_alert.attack_stage` 保持一致，但可以表达案件级别进展：

- `recon`
- `probe`
- `exploit`
- `persistence`
- `command_execution`
- `lateral_prep`
- `post_exploit`
- `unknown`

##### 15.5.5 `case_target_asset.role` 推荐枚举

资产在案件中的角色建议包括：

- `primary_target`
- `related_target`
- `scanned`
- `exploited`
- `compromised`
- `internal_target`

这能支撑案件详情页中的“目标系统”模块，区分：

- 哪个系统只是被探测
- 哪个系统被利用
- 哪个系统已经疑似失陷

##### 15.5.6 `timeline_event` 设计原则

`timeline_event` 不是保存每条原始告警，而是保存案件中值得用户阅读的关键阶段节点。

设计原则：

- 每个节点只表达一个关键动作或阶段
- 每个节点挂少量关键证据
- 不把大量原始日志直接放进时间线
- 时间线用于讲清攻击过程，不用于替代证据库

建议字段补充：

- `title`
- `stage`
- `summary`
- `evidence_refs`
- `related_alert_ids`
- `related_asset_ids`
- `related_artifact_ids`

##### 15.5.7 `evidence_item` 设计原则

`evidence_item` 是用户和 Agent 能直接引用的证据切片。它应比原始日志短，但必须能追溯到原始记录。

建议 `evidence_type` 枚举包括：

- `waf_alert`
- `http_request`
- `host_file`
- `process_event`
- `network_flow`
- `intel_hit`
- `manual_note`

证据必须尽量支持：

- 摘要展示
- 原始引用
- 关联时间线
- 关联评分事件
- 关联报告输出

##### 15.5.8 `attacker_profile` 与 `case_actor_link`

`attacker_profile` 表达跨案件复用的攻击者画像或攻击活动画像，不代表真实自然人身份。

`case_actor_link` 表达某个案件与某个画像之间的关系。关联不能只靠单个 IP，应尽量记录结构化理由。

建议 `case_actor_link.link_type` 包括：

- `same_infra`
- `same_ttp`
- `same_artifact`
- `same_targeting`
- `same_asset_progression`
- `suspected_same_operator`

建议 `link_confidence` 用低、中、高或 0-100 表达，但前端默认展示为低、中、高更直观。

##### 15.5.9 `attack_artifact` 设计原则

`attack_artifact` 用于串联跨天、跨 IP、跨设备的攻击链。

建议 `artifact_type` 包括：

- `webshell_path`
- `file_hash`
- `malicious_domain`
- `c2_address`
- `payload_fingerprint`
- `uri_pattern`
- `credential_hint`

在三天攻击链场景中，`webshell_path` 往往比 IP 更适合作为强关联证据。

##### 15.5.10 三天攻击链示例映射

以下示例用于说明模型如何表达“多天、多 IP、多目标”的攻击链：

- 第一天：IP1 扫描系统 A / B / C
  - `normalized_alert`：多条 `recon/probe` 告警
  - `case_target_asset`：系统 A / B / C 角色为 `scanned`
  - `timeline_event`：`Day 1 · 侦察`

- 第二天：攻击者利用系统 A 并上传 WebShell
  - `normalized_alert`：`exploit`、`persistence` 告警
  - `case_target_asset`：系统 A 角色升级为 `compromised`
  - `attack_artifact`：记录 WebShell 路径或文件 hash
  - `timeline_event`：`Day 2 · 利用与落地`
  - `score_event`：因为 WebShell 落地而升分

- 第三天：IP2 访问同一 WebShell 并开始内网扫描
  - `normalized_alert`：`command_execution`、`lateral_prep` 告警
  - `case_actor_link`：基于同一 WebShell 路径和连续攻击阶段，将 IP2 关联到同一画像
  - `timeline_event`：`Day 3 · 控制与横向准备`
  - `score_event`：因为内网扫描出现而升分

该映射说明：

- 系统不是用 IP 强行串案
- 系统通过 `attack_artifact`、`timeline_event`、`case_actor_link` 串联攻击链
- 每个关键判断都有对应证据和关联理由

### 15.6 接入与解析域

#### `data_source`

表示一个持续取数的数据源。

建议最小字段：

- `source_id`
- `source_name`
- `source_mode`（`cli` / `api`）
- `device_type`
- `vendor`
- `product`
- `enabled`
- `schedule`
- `status`
- `parser_profile_id`

#### `source_run`

表示一次实际的拉取执行记录。

建议最小字段：

- `source_run_id`
- `source_id`
- `started_at`
- `ended_at`
- `status`
- `fetched_count`
- `normalized_count`
- `error_summary`

#### `upload_job`

表示一次手工上传任务。

建议最小字段：

- `upload_job_id`
- `upload_type`
- `file_name`
- `submitted_by`
- `submitted_at`
- `status`
- `parser_profile_id`
- `result_summary`

#### `parser_profile`

表示一个设备解析画像。

建议最小字段：

- `parser_profile_id`
- `device_type`
- `vendor`
- `product`
- `input_format`
- `status`
- `approved_by_user`
- `created_at`

#### `parser_profile_version`

表示解析规则版本。

建议最小字段：

- `parser_profile_version_id`
- `parser_profile_id`
- `version_no`
- `field_mapping`
- `normalization_rules`
- `created_at`
- `effective_from`
- `status`

##### 15.6.1 `data_source` 字段语义

`data_source` 表示一个可持续运行的数据接入源，主要服务于接入中心底部的“信源运行状况”视图。

建议对关键字段做如下解释：

- `source_mode`
  - 接入方式，当前建议为 `cli` 或 `api`

- `device_type`
  - 数据源对应的安全设备类型，如 `waf`、`edr`、`dpi`

- `enabled`
  - 是否参与调度；关闭后不应再自动拉取

- `schedule`
  - 调度表达，可先用简单字符串表示，如 `*/5 * * * *` 或 `every_5m`

- `status`
  - 当前数据源的整体状态，不等于某次执行状态

- `parser_profile_id`
  - 当前默认绑定的解析画像

##### 15.6.2 `data_source.status` 推荐枚举

- `active`
- `disabled`
- `degraded`
- `error`
- `pending_setup`

其中：

- `active` 表示可正常运行
- `degraded` 表示可运行但近期存在异常
- `error` 表示持续失败或不可用
- `pending_setup` 表示接入信息尚未配置完整

##### 15.6.3 `source_run` 设计原则

`source_run` 不是配置对象，而是一次实际执行记录。它用于回答：

- 最近一次有没有拉到数据
- 拉到了多少原始事件
- 成功标准化了多少
- 最近失败原因是什么

建议补充字段：

- `trigger_type`（如 `schedule`、`manual`、`retry`）
- `raw_event_count`
- `failed_count`
- `parser_profile_version_id`
- `result_summary`

##### 15.6.4 `source_run.status` 推荐枚举

- `running`
- `success`
- `partial_success`
- `failed`
- `cancelled`

其中 `partial_success` 很重要，因为安全日志接入经常出现：

- 拉取成功但标准化部分失败
- 多批次中只有一部分成功
- 个别记录因字段缺失进入待复核

##### 15.6.5 `upload_job` 字段语义

`upload_job` 表示用户手工导入的一次任务，它不是持续信源，但在 PoC 和离线研判中非常重要。

建议对关键字段做如下解释：

- `upload_type`
  - 上传内容类型，如 `asset_file`、`alert_file`、`log_file`、`sample_alert`

- `submitted_by`
  - 谁发起了上传任务

- `status`
  - 当前上传任务处理状态

- `parser_profile_id`
  - 若该上传需要解析规则，则记录绑定的解析画像；资产清单上传可为空

- `result_summary`
  - 处理结果摘要，如“导入 120 条，标准化 118 条，2 条待映射”

##### 15.6.6 `upload_job.status` 推荐枚举

- `uploaded`
- `queued`
- `processing`
- `waiting_mapping`
- `needs_review`
- `completed`
- `failed`

其中：

- `waiting_mapping` 表示还没有合适的解析规则
- `needs_review` 表示规则能跑，但结果不稳定或关键字段缺失

##### 15.6.7 `parser_profile` 设计原则

`parser_profile` 代表“某类设备输入格式的解析画像”，它不直接保存全部规则细节，而是承担“设备识别 + 规则集合”的角色。

建议补充字段：

- `profile_name`
- `input_format`
- `sample_count`
- `last_validated_at`
- `latest_version_no`
- `notes`

建议 `status` 枚举：

- `draft`
- `active`
- `deprecated`
- `disabled`

其中：

- `draft` 表示还在校准
- `active` 表示当前可投入批量使用
- `deprecated` 表示仍可追溯历史，但不建议再给新数据用

##### 15.6.8 `parser_profile_version` 设计原则

`parser_profile_version` 才是真正驱动标准化的版本对象。

建议补充字段：

- `mapping_confidence`
- `created_from_sample_ids`
- `approved_by`
- `change_summary`
- `validation_status`

建议 `status` / `validation_status` 至少支持：

- `draft`
- `validated`
- `active`
- `superseded`
- `failed_validation`

这能支撑：

- 规则从草稿到生效
- 用户修正规则后版本递增
- 历史告警仍然保留旧版本追溯关系

##### 15.6.9 接入中心页面映射

当前接入中心页面与接入域模型的关系建议如下：

- 顶部 `CLI 配置 / API 配置`
  - 主要依赖：`data_source`

- 顶部 `手动上传`
  - 主要依赖：`upload_job`

- 底部运行状态区
  - 主要依赖：`data_source` + `source_run`

- 解析规则管理入口
  - 主要依赖：`parser_profile` + `parser_profile_version`

##### 15.6.10 最小运行示例

以一个 `WAF-01` 持续取数信源为例：

- `data_source`
  - `source_name = "WAF-01"`
  - `source_mode = "cli"`
  - `device_type = "waf"`
  - `status = "active"`
  - `parser_profile_id = "pp_waf_vendor_a"`

- 一次 `source_run`
  - `status = "partial_success"`
  - `raw_event_count = 43`
  - `normalized_count = 40`
  - `failed_count = 3`
  - `result_summary = "3 条字段缺失，进入待复核"`

- 若用户手工上传一份样例告警文件：
  - 生成一条 `upload_job`
  - `upload_type = "sample_alert"`
  - `status = "waiting_mapping"`
  - 后续触发 Agent 辅助映射并生成新的 `parser_profile_version`

### 15.7 反馈、情报与噪音域

#### `feedback_entry`

表示用户对案件、资产、画像、证据或评分的轻量反馈。

建议最小字段：

- `feedback_id`
- `target_type`（如 `case`、`asset`、`attacker_profile`、`timeline_event`、`score_event`）
- `target_id`
- `feedback_type`
- `comment`
- `submitted_by`
- `submitted_at`
- `status`

建议 `feedback_type` 包括：

- `confirm`
- `disagree`
- `mark_false_positive`
- `needs_review`
- `add_note`
- `add_evidence`

该对象用于承接案件详情页中的“反馈与修正”入口，但不要求每个案件都必须有反馈。

#### `correction_request`

表示用户希望系统修正某个结构化判断的请求。

建议最小字段：

- `correction_id`
- `target_type`
- `target_id`
- `correction_type`
- `old_value_summary`
- `new_value_summary`
- `reason`
- `submitted_by`
- `submitted_at`
- `status`
- `applied_at`

建议 `correction_type` 包括：

- `asset_alias_fix`
- `case_actor_link_fix`
- `target_scope_fix`
- `timeline_attribution_fix`
- `parser_mapping_fix`
- `score_reason_fix`

该对象用于把用户修正转化为可审计任务，而不是把修正只留在聊天上下文中。

#### `intel_cache`

表示外部威胁情报查询结果缓存。

建议最小字段：

- `intel_cache_id`
- `indicator_type`（如 `ip`、`domain`、`hash`、`url`）
- `indicator_value`
- `provider`
- `verdict`
- `tags`
- `confidence`
- `queried_at`
- `expires_at`
- `raw_ref`

该对象用于支撑按需情报补证，并避免重复查询第三方情报平台。

#### `noise_rule`

表示用户或系统沉淀出的误报、噪音或低价值扫描规则。

建议最小字段：

- `noise_rule_id`
- `rule_name`
- `scope_type`（如 `global`、`asset`、`device`、`rule_id`）
- `match_condition`
- `effect`（如 `suppress`、`downgrade`、`aggregate_only`）
- `reason`
- `created_from_feedback_id`
- `status`
- `created_at`

该对象用于支撑：

- 已知误报沉淀
- 高频低价值规则降噪
- 用户标记误报后的长期记忆

### 15.8 输出域

#### `notification`

表示一次通知草稿或发送记录。

建议最小字段：

- `notification_id`
- `case_id`
- `channel_type`
- `template_name`
- `payload_summary`
- `status`
- `created_at`
- `sent_at`

#### `report`

表示一份案件报告草稿或导出物。

建议最小字段：

- `report_id`
- `case_id`
- `title`
- `template_name`
- `format`
- `status`
- `content_ref`
- `generated_at`
- `exported_at`

### 15.9 与页面的映射关系

当前页面与数据模型的对应关系如下：

- `案件列表页` 主要依赖：`case`、`attacker_profile`、`case_target_asset`
- `案件详情页` 主要依赖：`case`、`timeline_event`、`evidence_item`、`case_actor_link`、`feedback_entry`
- `资产清单页` 主要依赖：`asset`、`asset_endpoint`、`asset_alias`
- `资产详情页` 主要依赖：`asset`、`asset_endpoint`、`asset_alias`、`case_target_asset`、`correction_request`
- `通知页` 主要依赖：`notification`
- `报告页` 主要依赖：`report`
- `接入中心` 主要依赖：`data_source`、`source_run`、`upload_job`、`parser_profile`

### 15.10 当前建模边界

本节仍然是第一版建模骨架，尚未细化到：

- 字段类型
- 索引设计
- 唯一键约束
- 状态机枚举全集
- 具体 JSON schema

这些内容应在下一轮细化中继续完成。
