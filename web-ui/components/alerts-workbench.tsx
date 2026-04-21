"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type UploadJob = {
  job_id: string;
  status: string;
  source: string;
  file_name: string;
  total_rows: number;
  mapped_rows: number;
  unmapped_rows: number;
  pending_rows: number;
  error_rows: number;
  created_at: string;
  updated_at: string;
};

type SampleGroup = {
  group_key: {
    source?: string | null;
    vendor?: string | null;
    product?: string | null;
    log_type?: string | null;
    rule_id?: string | null;
  };
  event_count: number;
  samples: Array<{
    raw_event_id: string;
    occurred_at?: string | null;
    payload?: { row?: Record<string, unknown> } | Record<string, unknown>;
  }>;
};

type AnalysisStatus = {
  run?: {
    run_id: string;
    status: string;
    summary?: string;
    started_at?: string;
    finished_at?: string | null;
  } | null;
  cost?: {
    trigger_mode?: string;
    model?: string | null;
    turns?: number | null;
    tool_calls?: number | null;
    usage_input_tokens?: number | null;
    usage_output_tokens?: number | null;
    usage_cached_input_tokens?: number | null;
    usage_total_tokens?: number | null;
    duration_ms?: number | null;
  } | null;
  steps?: Array<{ tool_name: string; call_count: number }>;
  event_state_counts?: Record<string, number>;
};

type ApplyPayload = {
  job?: UploadJob;
  apply_result?: {
    processed?: number;
    mapped?: number;
    unmapped?: number;
    created_alert_ids?: string[];
    asset_resolved_count?: number;
    asset_auto_created_count?: number;
    asset_unresolved_count?: number;
  };
  trigger_result?: {
    status?: string;
    run_id?: string | null;
  } | null;
};

function asJob(value: unknown): UploadJob | null {
  if (!value || typeof value !== "object") {
    return null;
  }
  const item = value as Record<string, unknown>;
  const jobId = typeof item.job_id === "string" ? item.job_id : "";
  if (!jobId) {
    return null;
  }
  return {
    job_id: jobId,
    status: String(item.status || "unknown"),
    source: String(item.source || ""),
    file_name: String(item.file_name || ""),
    total_rows: Number(item.total_rows || 0),
    mapped_rows: Number(item.mapped_rows || 0),
    unmapped_rows: Number(item.unmapped_rows || 0),
    pending_rows: Number(item.pending_rows || 0),
    error_rows: Number(item.error_rows || 0),
    created_at: String(item.created_at || ""),
    updated_at: String(item.updated_at || ""),
  };
}

function formatNumber(value: unknown): string {
  const num = Number(value || 0);
  return Number.isFinite(num) ? num.toLocaleString("zh-CN") : "0";
}

export default function AlertsWorkbench() {
  const [activeTab, setActiveTab] = useState<"file" | "integration">("file");
  const [loadingUpload, setLoadingUpload] = useState(false);
  const [loadingSample, setLoadingSample] = useState(false);
  const [loadingApply, setLoadingApply] = useState(false);
  const [loadingAnalyze, setLoadingAnalyze] = useState(false);
  const [polling, setPolling] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [currentJob, setCurrentJob] = useState<UploadJob | null>(null);
  const [mapBootstrap, setMapBootstrap] = useState<Record<string, unknown> | null>(null);
  const [sampleGroups, setSampleGroups] = useState<SampleGroup[]>([]);
  const [applyPayload, setApplyPayload] = useState<ApplyPayload | null>(null);
  const [analysisStatus, setAnalysisStatus] = useState<AnalysisStatus | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<Record<string, unknown> | null>(null);

  const currentJobId = currentJob?.job_id || null;

  const canConfirmMapping = useMemo(() => {
    return Boolean(currentJobId);
  }, [currentJobId]);

  async function loadSample(jobId: string) {
    setLoadingSample(true);
    try {
      const response = await fetch(`/api/alerts/uploads/${jobId}/sample?limit_groups=5&samples_per_group=1`, {
        cache: "no-store",
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(String(payload?.detail || `抽样失败(${response.status})`));
      }
      const groups = Array.isArray(payload?.groups) ? payload.groups : [];
      setSampleGroups(groups as SampleGroup[]);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "抽样失败");
    } finally {
      setLoadingSample(false);
    }
  }

  async function loadAnalysis(jobId: string) {
    const response = await fetch(`/api/alerts/uploads/${jobId}/analysis`, { cache: "no-store" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(String(payload?.detail || `分析状态拉取失败(${response.status})`));
    }
    setAnalysisStatus(payload as AnalysisStatus);
    return payload as AnalysisStatus;
  }

  async function onUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const file = formData.get("file");
    if (!(file instanceof File) || !file.name) {
      setError("请先选择 CSV 文件。");
      return;
    }

    setLoadingUpload(true);
    setError(null);
    setSuccess(null);
    setApplyPayload(null);
    setAnalyzeResult(null);
    setAnalysisStatus(null);
    setSampleGroups([]);
    setMapBootstrap(null);
    try {
      const response = await fetch("/api/alerts/uploads/import", {
        method: "POST",
        body: formData,
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(String(payload?.detail || `上传失败(${response.status})`));
      }
      const job = asJob(payload?.import_result?.job);
      if (!job) {
        throw new Error("上传成功但未返回任务信息");
      }
      setCurrentJob(job);
      setMapBootstrap((payload?.map_bootstrap as Record<string, unknown>) || null);
      setSuccess(`上传成功：${job.job_id}（原始告警 ${formatNumber(job.total_rows)} 条）`);
      await loadSample(job.job_id);
      try {
        await loadAnalysis(job.job_id);
      } catch {
        setAnalysisStatus(null);
      }
      form.reset();
    } catch (uploadError) {
      setError(uploadError instanceof Error ? uploadError.message : "上传失败");
    } finally {
      setLoadingUpload(false);
    }
  }

  async function onConfirmMapping() {
    if (!currentJobId) {
      setError("请先上传并生成任务。");
      return;
    }
    setLoadingApply(true);
    setError(null);
    setSuccess(null);
    try {
      const response = await fetch(`/api/alerts/uploads/${currentJobId}/apply`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          limit: 500,
          include_unmapped: true,
          trigger_after_apply: false,
          trigger_dry_run: false,
        }),
      });
      const payload = (await response.json().catch(() => ({}))) as ApplyPayload;
      if (!response.ok) {
        throw new Error(String((payload as any)?.detail || `确认入库失败(${response.status})`));
      }
      setApplyPayload(payload);
      const job = asJob(payload?.job);
      if (job) {
        setCurrentJob(job);
      }
      const mapped = Number(payload?.apply_result?.mapped || 0);
      const unmapped = Number(payload?.apply_result?.unmapped || 0);
      setSuccess(`映射入库完成：mapped=${mapped}，unmapped=${unmapped}`);
      await loadAnalysis(currentJobId);
    } catch (applyError) {
      setError(applyError instanceof Error ? applyError.message : "确认入库失败");
    } finally {
      setLoadingApply(false);
    }
  }

  async function onAnalyze() {
    if (!currentJobId) {
      setError("请先上传任务。");
      return;
    }
    setLoadingAnalyze(true);
    setError(null);
    setSuccess(null);
    try {
      const response = await fetch(`/api/alerts/uploads/${currentJobId}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ dry_run: false }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(String(payload?.detail || `触发分析失败(${response.status})`));
      }
      setAnalyzeResult(payload as Record<string, unknown>);
      setPolling(true);
      setSuccess("已触发任务级分析，正在刷新进展…");
    } catch (analyzeError) {
      setError(analyzeError instanceof Error ? analyzeError.message : "触发分析失败");
    } finally {
      setLoadingAnalyze(false);
    }
  }

  useEffect(() => {
    if (!polling || !currentJobId) {
      return undefined;
    }
    let active = true;
    const timer = setInterval(async () => {
      if (!active) {
        return;
      }
      try {
        const latest = await loadAnalysis(currentJobId);
        const status = String(latest?.run?.status || "").toLowerCase();
        if (["success", "failed", "dry_run_success"].includes(status)) {
          setPolling(false);
        }
      } catch {
        setPolling(false);
      }
    }, 3000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [polling, currentJobId]);

  return (
    <>
      <div className="card alerts-top">
        <div className="alerts-tabs">
          <button
            type="button"
            className={`alerts-tab ${activeTab === "file" ? "active" : ""}`}
            onClick={() => setActiveTab("file")}
          >
            文件上传
          </button>
          <button
            type="button"
            className={`alerts-tab ${activeTab === "integration" ? "active" : ""}`}
            onClick={() => setActiveTab("integration")}
          >
            数据对接（预留）
          </button>
        </div>

        {activeTab === "file" ? (
          <form onSubmit={onUpload} className="alerts-form">
            <input type="file" name="file" accept=".csv,text/csv" required />
            <div className="alerts-form-grid">
              <input name="vendor" placeholder="vendor（可选）" />
              <input name="product" placeholder="product（可选）" />
              <input name="log_type" placeholder="log_type（可选）" />
              <input name="occurred_at_column" placeholder="时间列名（可选）" />
              <input name="rule_id_column" placeholder="规则列名（可选）" />
              <input name="job_id" placeholder="job_id（可选）" />
            </div>
            <div className="alerts-actions">
              <button type="submit" disabled={loadingUpload}>
                {loadingUpload ? "上传中..." : "上传并抽样映射"}
              </button>
              <button type="button" disabled={!canConfirmMapping || loadingApply} onClick={onConfirmMapping}>
                {loadingApply ? "入库中..." : "确认映射并入库"}
              </button>
              <button type="button" disabled={!canConfirmMapping || loadingAnalyze} onClick={onAnalyze}>
                {loadingAnalyze ? "触发中..." : "分析当前任务"}
              </button>
            </div>
          </form>
        ) : (
          <p className="meta">数据对接入口预留中，MVP 阶段优先文件上传闭环。</p>
        )}

        {error ? <p className="meta alerts-error">{error}</p> : null}
        {success ? <p className="meta alerts-success">{success}</p> : null}
      </div>

      <div className="alerts-bottom">
        <div className="card">
          <h2>当前任务</h2>
          {!currentJob ? <p className="meta">暂无任务，请先上传文件。</p> : null}
          {currentJob ? (
            <>
              <p className="meta">任务：{currentJob.job_id}</p>
              <p className="meta">状态：{currentJob.status}</p>
              <p className="meta">来源：{currentJob.source}</p>
              <p className="meta">文件：{currentJob.file_name || "-"}</p>
              <p className="meta">告警数量（原始行）：{formatNumber(currentJob.total_rows)}</p>
              <p className="meta">
                映射统计：mapped={formatNumber(currentJob.mapped_rows)} / unmapped=
                {formatNumber(currentJob.unmapped_rows)} / pending={formatNumber(currentJob.pending_rows)}
              </p>
            </>
          ) : null}
        </div>

        <div className="card">
          <h2>抽样映射预览（5 条）</h2>
          {mapBootstrap ? (
            <p className="meta">
              Agent 映射建议：map_id={String(mapBootstrap.map_id || "-")}，字段=
              {Array.isArray(mapBootstrap.field_map_keys) ? mapBootstrap.field_map_keys.join(", ") : "-"}
            </p>
          ) : (
            <p className="meta">暂无映射建议。</p>
          )}
          {loadingSample ? <p className="meta">抽样加载中...</p> : null}
          {sampleGroups.length === 0 ? <p className="meta">暂无抽样样本。</p> : null}
          {sampleGroups.map((group) => {
            const sample = group.samples?.[0];
            const rowPayload =
              sample?.payload && typeof sample.payload === "object" && "row" in sample.payload
                ? (sample.payload as { row?: Record<string, unknown> }).row || {}
                : {};
            return (
              <div className="subcard" key={`${group.group_key.source}-${group.group_key.rule_id}-${sample?.raw_event_id}`}>
                <p className="meta">
                  source={group.group_key.source || "-"} / vendor={group.group_key.vendor || "-"} / product=
                  {group.group_key.product || "-"} / count={group.event_count}
                </p>
                <p className="meta">sample={sample?.raw_event_id || "-"}</p>
                <pre className="alerts-pre">{JSON.stringify(rowPayload, null, 2)}</pre>
              </div>
            );
          })}
        </div>

        <div className="card">
          <h2>入库与分析进展</h2>
          {applyPayload?.apply_result ? (
            <p className="meta">
              入库结果：processed={formatNumber(applyPayload.apply_result.processed)}，mapped=
              {formatNumber(applyPayload.apply_result.mapped)}，unmapped=
              {formatNumber(applyPayload.apply_result.unmapped)}
            </p>
          ) : (
            <p className="meta">尚未确认入库。</p>
          )}
          {analyzeResult ? (
            <p className="meta">
              最近触发：status={String(analyzeResult.status || "-")}，run_id={String(analyzeResult.run_id || "-")}
            </p>
          ) : null}
          {polling ? <p className="meta">分析中：每 3 秒刷新一次...</p> : null}
          {analysisStatus?.run ? (
            <>
              <p className="meta">
                当前 run：{analysisStatus.run.run_id} · {analysisStatus.run.status}
              </p>
              <pre className="alerts-pre">{String(analysisStatus.run.summary || "")}</pre>
            </>
          ) : (
            <p className="meta">暂无 run 结果。</p>
          )}
          {analysisStatus?.event_state_counts ? (
            <p className="meta">事件状态：{JSON.stringify(analysisStatus.event_state_counts)}</p>
          ) : null}
        </div>

        <div className="card">
          <h2>成本（Token/Tools/耗时）</h2>
          {analysisStatus?.cost ? (
            <>
              <p className="meta">model={String(analysisStatus.cost.model || "-")}</p>
              <p className="meta">turns={formatNumber(analysisStatus.cost.turns)} / tools={formatNumber(analysisStatus.cost.tool_calls)}</p>
              <p className="meta">
                tokens: in={formatNumber(analysisStatus.cost.usage_input_tokens)} / out=
                {formatNumber(analysisStatus.cost.usage_output_tokens)} / cached=
                {formatNumber(analysisStatus.cost.usage_cached_input_tokens)} / total=
                {formatNumber(analysisStatus.cost.usage_total_tokens)}
              </p>
              <p className="meta">duration={formatNumber(analysisStatus.cost.duration_ms)} ms</p>
            </>
          ) : (
            <p className="meta">暂无成本数据。</p>
          )}
          <h3>步骤（Tool 调用）</h3>
          {!analysisStatus?.steps || analysisStatus.steps.length === 0 ? (
            <p className="meta">暂无步骤数据。</p>
          ) : (
            analysisStatus.steps.map((item) => (
              <p className="meta" key={item.tool_name}>
                {item.tool_name} × {item.call_count}
              </p>
            ))
          )}
        </div>
      </div>
    </>
  );
}
