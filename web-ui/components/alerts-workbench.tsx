"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldContent, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

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
    asset_resolved_count?: number;
    asset_auto_created_count?: number;
    asset_unresolved_count?: number;
  };
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

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  const normalized = status.toLowerCase();
  if (normalized === "success" || normalized === "completed") {
    return "secondary";
  }
  if (normalized === "failed" || normalized === "error") {
    return "destructive";
  }
  if (normalized === "running" || normalized === "processing") {
    return "default";
  }
  return "outline";
}

export default function AlertsWorkbench() {
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

  const currentJobId = currentJob?.job_id || null;
  const canRunActions = useMemo(() => Boolean(currentJobId), [currentJobId]);

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
    setSampleGroups([]);
    setAnalysisStatus(null);
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
      await loadSample(job.job_id);
      try {
        await loadAnalysis(job.job_id);
      } catch {}
      setSuccess(`上传成功，任务 ${job.job_id} 已创建。`);
      form.reset();
    } catch (uploadError) {
      setError(uploadError instanceof Error ? uploadError.message : "上传失败");
    } finally {
      setLoadingUpload(false);
    }
  }

  async function onConfirmMapping() {
    if (!currentJobId) {
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
      const updatedJob = asJob(payload?.job);
      if (updatedJob) {
        setCurrentJob(updatedJob);
      }
      await loadAnalysis(currentJobId);
      setSuccess("映射确认成功，已完成入库。");
    } catch (applyError) {
      setError(applyError instanceof Error ? applyError.message : "确认入库失败");
    } finally {
      setLoadingApply(false);
    }
  }

  async function onAnalyze() {
    if (!currentJobId) {
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
      setSuccess("已触发当前任务分析，正在刷新进展。");
      setPolling(true);
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
    <div className="flex flex-col gap-4">
      <section className="flex flex-col gap-4 rounded-xl border bg-background p-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-base font-semibold">输入配置</h2>
          {currentJob ? <Badge variant={statusVariant(currentJob.status)}>{currentJob.status}</Badge> : null}
        </div>
        <Separator />
        <Tabs defaultValue="file">
          <TabsList>
            <TabsTrigger value="file">文件上传</TabsTrigger>
            <TabsTrigger value="integration">数据对接（预留）</TabsTrigger>
          </TabsList>
          <TabsContent value="file" className="pt-3">
            <form onSubmit={onUpload} className="flex flex-col gap-4">
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="file">CSV 文件</FieldLabel>
                  <Input id="file" type="file" name="file" accept=".csv,text/csv" required />
                </Field>
              </FieldGroup>
              <FieldGroup className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <Field>
                  <FieldLabel htmlFor="vendor">Vendor</FieldLabel>
                  <FieldContent>
                    <Input id="vendor" name="vendor" placeholder="可选" />
                  </FieldContent>
                </Field>
                <Field>
                  <FieldLabel htmlFor="product">Product</FieldLabel>
                  <FieldContent>
                    <Input id="product" name="product" placeholder="可选" />
                  </FieldContent>
                </Field>
                <Field>
                  <FieldLabel htmlFor="log_type">Log Type</FieldLabel>
                  <FieldContent>
                    <Input id="log_type" name="log_type" placeholder="可选" />
                  </FieldContent>
                </Field>
                <Field>
                  <FieldLabel htmlFor="occurred_at_column">时间列名</FieldLabel>
                  <FieldContent>
                    <Input id="occurred_at_column" name="occurred_at_column" placeholder="可选" />
                  </FieldContent>
                </Field>
                <Field>
                  <FieldLabel htmlFor="rule_id_column">规则列名</FieldLabel>
                  <FieldContent>
                    <Input id="rule_id_column" name="rule_id_column" placeholder="可选" />
                  </FieldContent>
                </Field>
                <Field>
                  <FieldLabel htmlFor="job_id">Job ID</FieldLabel>
                  <FieldContent>
                    <Input id="job_id" name="job_id" placeholder="可选" />
                  </FieldContent>
                </Field>
              </FieldGroup>
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={loadingUpload}>
                  {loadingUpload ? "上传中..." : "上传并抽样映射"}
                </Button>
                <Button type="button" variant="outline" disabled={!canRunActions || loadingApply} onClick={onConfirmMapping}>
                  {loadingApply ? "入库中..." : "确认映射并入库"}
                </Button>
                <Button type="button" variant="outline" disabled={!canRunActions || loadingAnalyze} onClick={onAnalyze}>
                  {loadingAnalyze ? "触发中..." : "分析当前任务"}
                </Button>
              </div>
            </form>
          </TabsContent>
          <TabsContent value="integration" className="pt-3">
            <Alert>
              <AlertTitle>数据对接模块预留</AlertTitle>
              <AlertDescription>当前 MVP 仅开放文件上传入口，后续接入 API / Syslog 等实时源。</AlertDescription>
            </Alert>
          </TabsContent>
        </Tabs>
        {error ? (
          <Alert variant="destructive">
            <AlertTitle>操作失败</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {success ? (
          <Alert>
            <AlertTitle>操作成功</AlertTitle>
            <AlertDescription>{success}</AlertDescription>
          </Alert>
        ) : null}
      </section>

      <section className="flex flex-col gap-4 rounded-xl border bg-background p-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-base font-semibold">输出结果</h2>
          <div className="flex flex-wrap gap-2">
            {currentJob ? <Badge variant="outline">{currentJob.job_id}</Badge> : <Badge variant="outline">未选择任务</Badge>}
            {polling ? <Badge>分析中</Badge> : null}
            {analysisStatus?.run?.status ? (
              <Badge variant={statusVariant(analysisStatus.run.status)}>{analysisStatus.run.status}</Badge>
            ) : null}
          </div>
        </div>
        <Separator />
        <Tabs defaultValue="overview">
          <TabsList>
            <TabsTrigger value="overview">任务概览</TabsTrigger>
            <TabsTrigger value="mapping">映射样本</TabsTrigger>
            <TabsTrigger value="analysis">分析进展</TabsTrigger>
          </TabsList>
          <TabsContent value="overview" className="pt-3">
            {!currentJob ? (
              <Alert>
                <AlertTitle>暂无任务</AlertTitle>
                <AlertDescription>请先在上方上传 CSV 并创建任务。</AlertDescription>
              </Alert>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>字段</TableHead>
                    <TableHead>值</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell>任务 ID</TableCell>
                    <TableCell>{currentJob.job_id}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>源标识</TableCell>
                    <TableCell>{currentJob.source || "-"}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>告警总数</TableCell>
                    <TableCell>{formatNumber(currentJob.total_rows)}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>映射统计</TableCell>
                    <TableCell>
                      mapped={formatNumber(currentJob.mapped_rows)} / unmapped={formatNumber(currentJob.unmapped_rows)} /
                      pending={formatNumber(currentJob.pending_rows)}
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>入库结果</TableCell>
                    <TableCell>
                      {applyPayload?.apply_result
                        ? `processed=${formatNumber(applyPayload.apply_result.processed)} mapped=${formatNumber(
                            applyPayload.apply_result.mapped
                          )} unmapped=${formatNumber(applyPayload.apply_result.unmapped)}`
                        : "-"}
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            )}
          </TabsContent>
          <TabsContent value="mapping" className="pt-3">
            <div className="flex flex-col gap-3">
              <p className="text-sm text-muted-foreground">
                映射建议：{mapBootstrap?.map_id ? String(mapBootstrap.map_id) : "暂无"}，字段：
                {Array.isArray(mapBootstrap?.field_map_keys) ? ` ${mapBootstrap?.field_map_keys.join(", ")}` : " -"}
              </p>
              {loadingSample ? <p className="text-sm text-muted-foreground">样本加载中...</p> : null}
              {sampleGroups.length === 0 ? <p className="text-sm text-muted-foreground">暂无样本。</p> : null}
              {sampleGroups.map((group) => {
                const sample = group.samples?.[0];
                const rowPayload =
                  sample?.payload && typeof sample.payload === "object" && "row" in sample.payload
                    ? (sample.payload as { row?: Record<string, unknown> }).row || {}
                    : {};
                return (
                  <div key={`${group.group_key.source}-${group.group_key.rule_id}-${sample?.raw_event_id}`} className="rounded-lg border p-3">
                    <p className="text-sm">
                      source={group.group_key.source || "-"} / vendor={group.group_key.vendor || "-"} / product=
                      {group.group_key.product || "-"} / count={group.event_count}
                    </p>
                    <p className="text-sm text-muted-foreground">sample={sample?.raw_event_id || "-"}</p>
                    <ScrollArea className="mt-2 h-28 rounded-md border p-2">
                      <pre className="text-xs">{JSON.stringify(rowPayload, null, 2)}</pre>
                    </ScrollArea>
                  </div>
                );
              })}
            </div>
          </TabsContent>
          <TabsContent value="analysis" className="pt-3">
            <div className="flex flex-col gap-3">
              {!analysisStatus?.run ? (
                <p className="text-sm text-muted-foreground">暂无分析结果。</p>
              ) : (
                <>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline">{analysisStatus.run.run_id}</Badge>
                    <Badge variant={statusVariant(analysisStatus.run.status)}>{analysisStatus.run.status}</Badge>
                  </div>
                  <ScrollArea className="h-28 rounded-md border p-2">
                    <pre className="text-xs whitespace-pre-wrap">{String(analysisStatus.run.summary || "")}</pre>
                  </ScrollArea>
                </>
              )}
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>成本项</TableHead>
                    <TableHead>值</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell>model</TableCell>
                    <TableCell>{String(analysisStatus?.cost?.model || "-")}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>tokens</TableCell>
                    <TableCell>
                      in={formatNumber(analysisStatus?.cost?.usage_input_tokens)} / out=
                      {formatNumber(analysisStatus?.cost?.usage_output_tokens)} / cached=
                      {formatNumber(analysisStatus?.cost?.usage_cached_input_tokens)} / total=
                      {formatNumber(analysisStatus?.cost?.usage_total_tokens)}
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>tool/turn/duration</TableCell>
                    <TableCell>
                      tools={formatNumber(analysisStatus?.cost?.tool_calls)} / turns=
                      {formatNumber(analysisStatus?.cost?.turns)} / duration=
                      {formatNumber(analysisStatus?.cost?.duration_ms)} ms
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Tool</TableHead>
                    <TableHead>调用次数</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(analysisStatus?.steps || []).length === 0 ? (
                    <TableRow>
                      <TableCell>暂无</TableCell>
                      <TableCell>0</TableCell>
                    </TableRow>
                  ) : (
                    (analysisStatus?.steps || []).map((step) => (
                      <TableRow key={step.tool_name}>
                        <TableCell>{step.tool_name}</TableCell>
                        <TableCell>{step.call_count}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </TabsContent>
        </Tabs>
      </section>
    </div>
  );
}
