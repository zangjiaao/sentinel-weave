# Web MVP（接入中心 + 四模块）Schema/UI 设计稿

日期：2026-04-20  
状态：Draft（待你确认后进入实现）  
范围：`接入中心`、`案件`、`资产`、`通知`、`报告`

---

## 1. 目标与约束

本版按 MVP 落地，核心约束如下：

- 同时覆盖五个模块：接入中心 + 四模块（案件/资产/通知/报告）
- 单租户、单团队，不引入 RBAC 与多租户
- 读为主；仅保留必要“预览型写操作”
- 案件详情必须包含：攻击者画像 + 证据链解释
- 通知/报告不做真实发送与导出，只做预览闭环

---

## 2. 总体设计原则

- 优先复用现有已验证表结构，新增最小必要表
- 状态枚举先统一，避免前后端各自解释
- API 采用“读模型优先”，保障 UI 可稳定消费
- 写操作默认走 `preview/dry-run`，不做破坏性变更
- 页面职责清晰，不在接入中心混入案件研判流程

---

## 3. Schema v1（MVP）

### 3.1 接入域（新增）

#### `data_sources`

- `source_id` (PK)
- `source_name`
- `source_mode`（`cli` / `api`）
- `device_type`
- `vendor`
- `product`
- `enabled`
- `schedule`
- `status`
- `parser_profile_id`（FK -> `parser_profiles.parser_profile_id`，MVP 可弱约束）
- `created_at`
- `updated_at`

#### `source_runs`

- `source_run_id` (PK)
- `source_id`
- `trigger_type`（`schedule` / `manual` / `retry`）
- `status`
- `started_at`
- `ended_at`
- `raw_event_count`
- `normalized_count`
- `failed_count`
- `parser_profile_version_id`
- `result_summary`
- `error_summary`

#### `parser_profiles`

- `parser_profile_id` (PK)
- `profile_name`
- `device_type`
- `vendor`
- `product`
- `input_format`
- `status`
- `created_at`
- `updated_at`

#### `parser_profile_versions`

- `parser_profile_version_id` (PK)
- `parser_profile_id`
- `version_no`
- `field_mapping_json`
- `normalization_rules_json`
- `validation_status`
- `status`
- `change_summary`
- `created_at`
- `effective_from`

### 3.2 接入域（复用）

复用现有表并做语义映射：

- `import_jobs` 视作 `upload_job`
- `raw_alert_events`
- `alert_normalization_maps`
- `unmapped_alert_events`

> 说明：本版不重命名老表，Web API 层统一输出为 `upload_job` 语义，避免一次性大迁移。

### 3.3 案件域（复用）

沿用现有主表：

- `cases`
- `case_alert_links`
- `timeline_events`
- `evidence`
- `case_actor_profiles`
- `case_actor_observations`
- `attacker_profiles`
- `case_actor_profile_links`
- `case_assessments`
- `link_decisions`
- `case_changes`

### 3.4 资产域（新增最小表）

#### `asset_identities`

- `identity_id` (PK)
- `asset_id`
- `identity_type`（`ip` / `domain` / `hostname` / `alias`）
- `identity_value`
- `is_primary`
- `confidence`
- `created_at`

### 3.5 通知域（复用）

- `notification_outbox`
- `escalation_decisions`

### 3.6 报告域（新增最小表）

#### `report_drafts`

- `report_id` (PK)
- `case_id`
- `title`
- `content_md`
- `status`（`created` / `previewed`）
- `created_at`
- `updated_at`

---

## 4. 状态枚举统一（v1）

### 4.1 上传任务 `upload_job.status`（映射 `import_jobs.status`）

- `uploaded`
- `queued`
- `processing`
- `waiting_mapping`
- `needs_review`
- `completed`
- `failed`

### 4.2 数据源 `data_source.status`

- `active`
- `disabled`
- `degraded`
- `error`
- `pending_setup`

### 4.3 信源执行 `source_run.status`

- `running`
- `success`
- `partial_success`
- `failed`
- `cancelled`

### 4.4 解析画像 `parser_profile.status`

- `draft`
- `active`
- `deprecated`
- `disabled`

### 4.5 画像版本校验 `parser_profile_version.validation_status`

- `draft`
- `validated`
- `failed_validation`

### 4.6 案件状态 `cases.status`（沿用）

- `open`
- `in_progress`
- `closed`
- `merged`

---

## 5. Web UI v1 信息架构

### 5.1 路由结构

- `/intake`
- `/cases`
- `/cases/[caseId]`
- `/assets`
- `/assets/[assetId]`
- `/notifications`
- `/reports`

### 5.2 接入中心 `/intake`

上半区（Tab）：

- CLI 配置
- API 配置
- 手动上传

下半区（统一状态）：

- 数据源运行状态（`data_sources + source_runs`）
- 上传任务状态（`upload_job` 语义）
- 解析规则版本状态（`parser_profiles + parser_profile_versions`）

### 5.3 案件模块

#### `/cases`（列表）

- 风险优先队列
- 关键列：`severity / stage / latest_activity / actor_summary / target_summary`

#### `/cases/[caseId]`（详情）

- 第一屏：攻击者画像 + 目标系统
- 第二屏：时间线（阶段化）+ 证据链解释
- 第三屏：评分/关联解释（只读）

### 5.4 资产模块

#### `/assets`

- 资产台账视角 + 风险视角切换

#### `/assets/[assetId]`

- 台账信息
- 身份归并（IP/域名/主机名/别名）
- 关联案件摘要

### 5.5 通知模块 `/notifications`

- 历史通知列表（状态/渠道/时间筛选）
- 仅支持预览，不执行真实发送

### 5.6 报告模块 `/reports`

- 报告草稿列表
- 报告预览（Markdown）
- 不执行真实导出

---

## 6. API v1（读优先）

### 6.1 Intake

- `GET /api/intake/sources`
- `GET /api/intake/sources/{source_id}/runs`
- `GET /api/intake/uploads`
- `GET /api/intake/uploads/{job_id}`
- `GET /api/intake/uploads/{job_id}/sample`
- `POST /api/intake/uploads/{job_id}/preview-map`
- `GET /api/intake/parsers`
- `GET /api/intake/parsers/{parser_profile_id}/versions`

### 6.2 Cases

- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `GET /api/cases/{case_id}/timeline`
- `GET /api/cases/{case_id}/actors`

### 6.3 Assets

- `GET /api/assets`
- `GET /api/assets/{asset_id}`
- `GET /api/assets/{asset_id}/cases`

### 6.4 Notifications

- `GET /api/notifications`
- `GET /api/notifications/{notification_id}`
- `POST /api/notifications/preview`

### 6.5 Reports

- `GET /api/reports`
- `GET /api/reports/{report_id}`
- `POST /api/reports/preview`

---

## 7. MVP 实施顺序（确认后执行）

1. 数据库迁移：补 `data_sources/source_runs/parser_profiles/parser_profile_versions/asset_identities/report_drafts`
2. 后端服务层：补接入域与四模块读模型查询
3. FastAPI 路由层：按 API v1 暴露
4. 前端壳（Next.js）：先做五模块页面骨架与列表/详情读取
5. 预览写操作：通知预览、报告预览、上传映射预览

---

## 8. 非目标（本版不做）

- 多租户与权限模型
- 通知真实发送
- 报告真实导出
- 复杂可视化攻击图编辑
- 规则 DSL 全量可视化编辑器
