"use client"

import { Fragment, useEffect, useMemo, useState } from "react"
import { ArrowRight, Wand2 } from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"

type UploadJob = {
  job_id: string
  status: string
  source: string
  file_name: string
  total_rows: number
  mapped_rows: number
  unmapped_rows: number
  pending_rows: number
  error_rows: number
  created_at?: string
  updated_at?: string
}

type UploadDraftStatus = "pending_template" | "ready" | "processing" | "done" | "failed"

type UploadDraft = {
  draftId: string
  file: File
  templateId?: string
  generatedMapping?: Record<string, string>
  status: UploadDraftStatus
  error?: string
  linkedJobId?: string
}

type SampleGroup = {
  group_key?: Record<string, unknown>
  event_count?: number
  samples?: SampleItem[]
}

type SampleItem = {
  raw_event_id?: string
  payload?: { row?: Record<string, unknown> } | Record<string, unknown>
}

type AnalysisStatus = {
  run?: {
    run_id?: string
    status?: string
    summary?: string
  } | null
  cost?: {
    model?: string | null
    turns?: number | null
    tool_calls?: number | null
    usage_input_tokens?: number | null
    usage_output_tokens?: number | null
    usage_cached_input_tokens?: number | null
    usage_total_tokens?: number | null
    duration_ms?: number | null
  } | null
}

type ApplyPayload = {
  job?: UploadJob
  apply_result?: {
    processed?: number
    mapped?: number
    unmapped?: number
  }
}

type MappingRow = {
  sourceField: string
  targetField: string
  auto: boolean
}

type MappingTemplate = {
  template_id: string
  template_name: string
  source_signature: string
  mapping: Record<string, string>
  created_at: string
}

type TargetSchemaField = {
  name: string
  required?: boolean
  description?: string
  example?: string
  source_aliases?: string[]
}

type TargetSchemaTemplate = {
  mapping_principles?: string[]
  fields?: TargetSchemaField[]
}

type MapBootstrap = {
  suggested_mapping?: Record<string, string>
  target_schema_template?: TargetSchemaTemplate
  field_names?: string[]
}

type UploadImportResponse = {
  detail?: string
  import_result?: {
    job?: unknown
  }
  map_bootstrap?: MapBootstrap
}

const TARGET_FIELDS = [
  "occurred_at",
  "title",
  "status",
  "severity",
  "attack_stage",
  "src_ip",
  "dst_ip",
  "asset_id",
  "rule_id",
  "attack_description",
]

const DEFAULT_TARGET_SCHEMA_TEMPLATE: TargetSchemaTemplate = {
  mapping_principles: ["优先映射语义明确字段", "同一源字段只映射一个目标字段", "缺失字段使用默认值"],
  fields: [
    {
      name: "occurred_at",
      required: true,
      description: "告警发生时间",
      example: "2026-04-22T09:30:00+08:00",
      source_aliases: ["occurred_at", "event_time", "timestamp", "time", "发生时间", "攻击时间"],
    },
    {
      name: "title",
      required: true,
      description: "告警标题",
      example: "SQL 注入尝试命中规则",
      source_aliases: ["title", "alert_title", "name", "告警标题", "攻击类型", "威胁情报"],
    },
    {
      name: "severity",
      required: true,
      description: "风险等级",
      example: "high",
      source_aliases: ["severity", "level", "risk_level", "风险等级", "告警等级"],
    },
    {
      name: "attack_stage",
      required: true,
      description: "攻击阶段",
      example: "exploit",
      source_aliases: ["attack_stage", "stage", "phase", "攻击阶段"],
    },
    {
      name: "src_ip",
      description: "攻击源 IP",
      example: "203.0.113.88",
      source_aliases: ["src_ip", "source_ip", "src", "attacker_ip", "源IP", "攻击IP"],
    },
    {
      name: "dst_ip",
      description: "目标 IP",
      example: "10.0.2.15",
      source_aliases: ["dst_ip", "destination_ip", "dst", "target_ip", "目标IP"],
    },
    {
      name: "asset_id",
      description: "目标资产",
      example: "asset_finance_api",
      source_aliases: ["asset_id", "asset", "target_asset", "hostname", "目标资产"],
    },
  ],
}

function asJob(value: unknown): UploadJob | null {
  if (!value || typeof value !== "object") {
    return null
  }
  const item = value as Record<string, unknown>
  const jobId = typeof item.job_id === "string" ? item.job_id : ""
  if (!jobId) {
    return null
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
    created_at: typeof item.created_at === "string" ? item.created_at : undefined,
    updated_at: typeof item.updated_at === "string" ? item.updated_at : undefined,
  }
}

function formatNumber(value: unknown): string {
  const num = Number(value || 0)
  return Number.isFinite(num) ? num.toLocaleString("zh-CN") : "0"
}

function formatTime(value: string | null | undefined): string {
  if (!value) {
    return "-"
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }
  return parsed.toLocaleString("zh-CN", { hour12: false })
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  const normalized = status.toLowerCase()
  if (["completed", "success", "done"].includes(normalized)) {
    return "outline"
  }
  if (["running", "processing", "waiting_mapping", "waiting_analysis"].includes(normalized)) {
    return "secondary"
  }
  if (["failed", "error"].includes(normalized)) {
    return "destructive"
  }
  return "default"
}

function draftStatusVariant(status: UploadDraftStatus): "default" | "secondary" | "destructive" | "outline" {
  if (status === "ready") return "secondary"
  if (status === "done") return "outline"
  if (status === "failed") return "destructive"
  if (status === "processing") return "default"
  return "default"
}

function draftStatusLabel(status: UploadDraftStatus): string {
  if (status === "pending_template") return "待选模板"
  if (status === "ready") return "可入库"
  if (status === "processing") return "入库中"
  if (status === "done") return "已完成"
  if (status === "failed") return "失败"
  return status
}

function toRowObject(sample: SampleItem | undefined): Record<string, unknown> {
  if (!sample || !sample.payload || typeof sample.payload !== "object") {
    return {}
  }
  if ("row" in sample.payload && sample.payload.row && typeof sample.payload.row === "object") {
    return sample.payload.row as Record<string, unknown>
  }
  return sample.payload as Record<string, unknown>
}

function guessTargetField(sourceField: string): string {
  const key = sourceField.toLowerCase()
  if (["time", "timestamp", "occurred_at", "event_time"].includes(key)) return "occurred_at"
  if (["src", "src_ip", "source_ip", "attacker_ip"].includes(key)) return "src_ip"
  if (["dst", "dst_ip", "destination_ip", "target_ip"].includes(key)) return "dst_ip"
  if (["asset_id", "host", "hostname", "target_asset"].includes(key)) return "asset_id"
  if (["severity", "level", "risk"].includes(key)) return "severity"
  if (["stage", "attack_stage", "phase"].includes(key)) return "attack_stage"
  if (["rule_id", "signature_id", "sid"].includes(key)) return "rule_id"
  if (["title", "alert_name", "name"].includes(key)) return "title"
  if (["status", "state"].includes(key)) return "status"
  if (["description", "detail", "msg", "message"].includes(key)) return "attack_description"
  return ""
}

function normalizeFieldKey(value: string): string {
  return value
    .toLowerCase()
    .split("")
    .filter((char) => /[a-z0-9\u4e00-\u9fa5]/.test(char))
    .join("")
}

function guessTargetFieldWithTemplate(sourceField: string, schema?: TargetSchemaTemplate): string {
  const normalizedSource = normalizeFieldKey(sourceField)
  const fields = Array.isArray(schema?.fields) ? schema.fields : []
  for (const item of fields) {
    const aliases = Array.isArray(item.source_aliases) ? item.source_aliases : []
    for (const alias of aliases) {
      const normalizedAlias = normalizeFieldKey(alias)
      if (!normalizedAlias) continue
      if (normalizedSource === normalizedAlias) {
        return item.name
      }
      if (normalizedAlias.length >= 4 && normalizedSource.includes(normalizedAlias)) {
        return item.name
      }
    }
  }
  return guessTargetField(sourceField)
}

function signatureOf(fields: string[]): string {
  return [...fields].sort((a, b) => a.localeCompare(b)).join("|")
}

function computeProgress(job: UploadJob): number {
  const total = Number(job.total_rows || 0)
  if (total <= 0) {
    return 0
  }
  const done = Number(job.mapped_rows || 0) + Number(job.unmapped_rows || 0) + Number(job.error_rows || 0)
  const raw = Math.round((done / total) * 100)
  return Math.max(0, Math.min(100, raw))
}

export default function AlertsWorkbench() {
  const [jobs, setJobs] = useState<UploadJob[]>([])
  const [loadingJobs, setLoadingJobs] = useState(false)
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null)

  const [uploadQueue, setUploadQueue] = useState<UploadDraft[]>([])
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)

  const [currentJob, setCurrentJob] = useState<UploadJob | null>(null)
  const [sampleGroups, setSampleGroups] = useState<SampleGroup[]>([])
  const [loadingSample, setLoadingSample] = useState(false)
  const [analysisStatus, setAnalysisStatus] = useState<AnalysisStatus | null>(null)
  const [applyPayload, setApplyPayload] = useState<ApplyPayload | null>(null)
  const [runningApply, setRunningApply] = useState(false)
  const [runningAnalyze, setRunningAnalyze] = useState(false)
  const [polling, setPolling] = useState(false)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [templateDialogOpen, setTemplateDialogOpen] = useState(false)
  const [mappingRows, setMappingRows] = useState<MappingRow[]>([])
  const [templateName, setTemplateName] = useState("")
  const [agentInstruction, setAgentInstruction] = useState("")
  const [mappingDraftId, setMappingDraftId] = useState<string | null>(null)
  const [selectedTemplate, setSelectedTemplate] = useState<MappingTemplate | null>(null)
  const [mapBootstrap, setMapBootstrap] = useState<MapBootstrap | null>(null)
  const [templates, setTemplates] = useState<MappingTemplate[]>([])

  const [error, setError] = useState<string | null>(null)

  const sampleRows = useMemo(
    () => sampleGroups.slice(0, 5).map((group) => toRowObject(group.samples?.[0])).filter((row) => Object.keys(row).length > 0),
    [sampleGroups],
  )
  const sourceFields = useMemo(() => {
    const bucket = new Set<string>()
    for (const row of sampleRows) {
      for (const key of Object.keys(row)) {
        bucket.add(key)
      }
    }
    return [...bucket]
  }, [sampleRows])
  const sourceSignature = useMemo(() => signatureOf(sourceFields), [sourceFields])
  const mappingDraft = useMemo(
    () => (mappingDraftId ? uploadQueue.find((item) => item.draftId === mappingDraftId) || null : null),
    [mappingDraftId, uploadQueue],
  )

  useEffect(() => {
    try {
      const raw = localStorage.getItem("alert_mapping_templates_v1")
      if (!raw) return
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) {
        setTemplates(parsed)
      }
    } catch {}
  }, [])

  function buildDraftId(file: File): string {
    return `${file.name}_${file.size}_${file.lastModified}`
  }

  function enqueueFiles(files: File[]) {
    if (files.length === 0) {
      return
    }
    setUploadQueue((prev) => {
      const existing = new Set(prev.map((item) => item.draftId))
      const next = [...prev]
      for (const file of files) {
        const draftId = buildDraftId(file)
        if (existing.has(draftId)) {
          continue
        }
        next.push({
          draftId,
          file,
          status: "pending_template",
        })
        existing.add(draftId)
      }
      return next
    })
  }

  async function loadJobs() {
    setLoadingJobs(true)
    try {
      const response = await fetch("/api/alerts/uploads?limit=50", { cache: "no-store" })
      const payload = (await response.json().catch(() => ({}))) as {
        detail?: string
        items?: unknown[]
      }
      if (!response.ok) {
        throw new Error(String(payload.detail || `任务列表拉取失败(${response.status})`))
      }
      const items = Array.isArray(payload.items) ? payload.items : []
      setJobs(items.map((item: unknown) => asJob(item)).filter((job): job is UploadJob => job !== null))
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "任务列表拉取失败")
    } finally {
      setLoadingJobs(false)
    }
  }

  async function loadSample(jobId: string) {
    setLoadingSample(true)
    try {
      const response = await fetch(`/api/alerts/uploads/${jobId}/sample?limit_groups=5&samples_per_group=1`, { cache: "no-store" })
      const payload = (await response.json().catch(() => ({}))) as {
        detail?: string
        groups?: unknown[]
      }
      if (!response.ok) {
        throw new Error(String(payload.detail || `样本拉取失败(${response.status})`))
      }
      const groups = Array.isArray(payload.groups) ? payload.groups : []
      setSampleGroups(groups as SampleGroup[])
      return groups as SampleGroup[]
    } finally {
      setLoadingSample(false)
    }
  }

  async function loadAnalysis(jobId: string) {
    const response = await fetch(`/api/alerts/uploads/${jobId}/analysis`, { cache: "no-store" })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new Error(String((payload as any)?.detail || `分析状态拉取失败(${response.status})`))
    }
    setAnalysisStatus(payload as AnalysisStatus)
    return payload as AnalysisStatus
  }

  useEffect(() => {
    loadJobs()
  }, [])

  useEffect(() => {
    if (!polling || !currentJob?.job_id) return
    let active = true
    const timer = setInterval(async () => {
      if (!active) return
      try {
        const latest = await loadAnalysis(currentJob.job_id)
        const status = String(latest?.run?.status || "").toLowerCase()
        await loadJobs()
        if (["success", "failed", "dry_run_success"].includes(status)) {
          setPolling(false)
          toast.success("分析完成")
        }
      } catch {
        setPolling(false)
      }
    }, 3000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [polling, currentJob?.job_id])

  async function previewDraftMapping(draftId: string) {
    const draft = uploadQueue.find((item) => item.draftId === draftId)
    if (!draft) {
      setError("未找到待处理文件")
      return
    }
    setError(null)
    setUploading(true)
    try {
      const formData = new FormData()
      formData.append("file", draft.file)
      formData.append("sample_limit", "5")
      const response = await fetch("/api/alerts/uploads/preview", {
        method: "POST",
        body: formData,
      })
      const payload = (await response.json().catch(() => ({}))) as {
        detail?: string
        preview?: {
          field_names?: string[]
          groups?: unknown[]
        }
        map_bootstrap?: MapBootstrap
      }
      if (!response.ok) {
        throw new Error(String(payload.detail || `预览失败(${response.status})`))
      }
      setMappingDraftId(draftId)
      setMapBootstrap(payload.map_bootstrap || null)

      const groups = Array.isArray(payload.preview?.groups) ? (payload.preview.groups as SampleGroup[]) : []
      setSampleGroups(groups)
      const rows = groups.slice(0, 5).map((group) => toRowObject(group.samples?.[0]))
      const previewFields = Array.isArray(payload.preview?.field_names) ? payload.preview.field_names : []
      const fields = previewFields.length > 0 ? previewFields : [...new Set(rows.flatMap((row) => Object.keys(row)))]
      const suggested = payload.map_bootstrap?.suggested_mapping || {}
      const schemaTemplate = payload.map_bootstrap?.target_schema_template || DEFAULT_TARGET_SCHEMA_TEMPLATE
      setMappingRows(
        fields.map((field) => ({
          sourceField: field,
          targetField: suggested[field] || guessTargetFieldWithTemplate(field, schemaTemplate),
          auto: Boolean(suggested[field] || guessTargetFieldWithTemplate(field, schemaTemplate)),
        })),
      )
      setDialogOpen(true)
      toast.success("预览完成，请确认映射并应用到当前文件")
    } catch (uploadError) {
      setError(uploadError instanceof Error ? uploadError.message : "预览失败")
    } finally {
      setUploading(false)
    }
  }

  async function createJobByConfirmingMapping(draft: UploadDraft): Promise<UploadJob> {
    if (!draft.file) {
      throw new Error("文件不存在")
    }
    const formData = new FormData()
    formData.append("file", draft.file)
    formData.append("apply_after_import", "false")
    formData.append("trigger_after_apply", "false")
    formData.append("trigger_dry_run", "false")
    formData.append("limit", "500")
    const response = await fetch("/api/alerts/uploads/import", {
      method: "POST",
      body: formData,
    })
    const payload = (await response.json().catch(() => ({}))) as UploadImportResponse
    if (!response.ok) {
      throw new Error(String(payload.detail || `创建任务失败(${response.status})`))
    }
    const job = asJob(payload.import_result?.job)
    if (!job) {
      throw new Error("创建任务成功但未返回任务信息")
    }
    setCurrentJob(job)
    setMapBootstrap(payload.map_bootstrap || mapBootstrap)
    await loadJobs()
    return job
  }

  function applyMappingToDraft() {
    if (!mappingDraftId) {
      setError("未找到当前映射文件")
      return
    }
    if (mappingRows.length === 0) {
      setError("当前映射为空")
      return
    }
    const mapping: Record<string, string> = {}
    for (const row of mappingRows) {
      if (row.sourceField && row.targetField) {
        mapping[row.sourceField] = row.targetField
      }
    }
    if (Object.keys(mapping).length === 0) {
      setError("请至少选择一个有效字段映射")
      return
    }
    setUploadQueue((prev) =>
      prev.map((item) =>
        item.draftId === mappingDraftId
          ? {
              ...item,
              generatedMapping: mapping,
              status: "ready",
              error: undefined,
            }
          : item,
      ),
    )
    setDialogOpen(false)
    toast.success("已将映射应用到当前文件")
  }

  async function ingestReadyDrafts() {
    const readyDrafts = uploadQueue.filter((item) => item.status === "ready")
    if (readyDrafts.length === 0) {
      setError("没有可入库文件，请先选择模板或生成映射")
      return
    }
    setError(null)
    setRunningApply(true)
    try {
      for (const draft of readyDrafts) {
        setUploadQueue((prev) =>
          prev.map((item) =>
            item.draftId === draft.draftId
              ? {
                  ...item,
                  status: "processing",
                  error: undefined,
                }
              : item,
          ),
        )
        const targetJob = await createJobByConfirmingMapping(draft)
        const selectedTemplate = draft.templateId ? templates.find((item) => item.template_id === draft.templateId) : null
        const templateMapping = selectedTemplate?.mapping || draft.generatedMapping || {}
        const response = await fetch(`/api/alerts/uploads/${targetJob.job_id}/apply`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            limit: 500,
            include_unmapped: true,
            trigger_after_apply: false,
            trigger_dry_run: false,
            template_mapping: templateMapping,
          }),
        })
        const payload = (await response.json().catch(() => ({}))) as ApplyPayload & {
          detail?: string
        }
        if (!response.ok) {
          throw new Error(String(payload.detail || `入库失败(${response.status})`))
        }
        setApplyPayload(payload)
        const updated = asJob(payload.job)
        if (updated) {
          setCurrentJob(updated)
        }
        setUploadQueue((prev) =>
          prev.map((item) =>
            item.draftId === draft.draftId
              ? {
                  ...item,
                  status: "done",
                  linkedJobId: targetJob.job_id,
                }
              : item,
          ),
        )
      }
      await loadJobs()
      toast.success(`已完成 ${readyDrafts.length} 个文件入库`)
    } catch (applyError) {
      const message = applyError instanceof Error ? applyError.message : "入库失败"
      setError(message)
      setUploadQueue((prev) =>
        prev.map((item) =>
          item.status === "processing"
            ? {
                ...item,
                status: "failed",
                error: message,
              }
            : item,
        ),
      )
    } finally {
      setRunningApply(false)
    }
  }

  async function triggerAnalyze() {
    if (!currentJob?.job_id) return
    setRunningAnalyze(true)
    setError(null)
    try {
      const response = await fetch(`/api/alerts/uploads/${currentJob.job_id}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ dry_run: false }),
      })
      const payload = (await response.json().catch(() => ({}))) as {
        detail?: string
      }
      if (!response.ok) {
        throw new Error(String(payload.detail || `触发分析失败(${response.status})`))
      }
      setPolling(true)
      await loadJobs()
      toast.success("已触发分析任务")
    } catch (analyzeError) {
      setError(analyzeError instanceof Error ? analyzeError.message : "触发分析失败")
    } finally {
      setRunningAnalyze(false)
    }
  }

  function saveTemplate() {
    if (!templateName.trim()) {
      toast.error("请先填写模板名称")
      return
    }
    if (mappingRows.length === 0) {
      toast.error("当前没有可保存的映射")
      return
    }
    const mapping: Record<string, string> = {}
    for (const row of mappingRows) {
      mapping[row.sourceField] = row.targetField
    }
    const next: MappingTemplate = {
      template_id: `tpl_${Date.now().toString(36)}`,
      template_name: templateName.trim(),
      source_signature: sourceSignature,
      mapping,
      created_at: new Date().toISOString(),
    }
    const merged = [next, ...templates]
    setTemplates(merged)
    localStorage.setItem("alert_mapping_templates_v1", JSON.stringify(merged))
    if (mappingDraftId) {
      setUploadQueue((prev) =>
        prev.map((item) =>
          item.draftId === mappingDraftId
            ? {
                ...item,
                templateId: next.template_id,
                generatedMapping: undefined,
                status: "ready",
                error: undefined,
              }
            : item,
        ),
      )
    }
    setTemplateName("")
    toast.success("映射模板已保存")
  }

  function openTemplateDetail(template: MappingTemplate) {
    setSelectedTemplate(template)
    setTemplateDialogOpen(true)
  }

  function removeTemplate(templateId: string) {
    const next = templates.filter((item) => item.template_id !== templateId)
    setTemplates(next)
    localStorage.setItem("alert_mapping_templates_v1", JSON.stringify(next))
    setUploadQueue((prev) =>
      prev.map((item) =>
        item.templateId === templateId
          ? {
              ...item,
              templateId: undefined,
              status: item.generatedMapping ? "ready" : "pending_template",
            }
          : item,
      ),
    )
    if (selectedTemplate?.template_id === templateId) {
      setSelectedTemplate(null)
      setTemplateDialogOpen(false)
    }
    toast.success("模板已删除")
  }

  function updateDraftTemplate(draftId: string, templateId: string) {
    setUploadQueue((prev) =>
      prev.map((item) => {
        if (item.draftId !== draftId) {
          return item
        }
        if (!templateId) {
          return {
            ...item,
            templateId: undefined,
            status: item.generatedMapping ? "ready" : "pending_template",
          }
        }
        return {
          ...item,
          templateId,
          generatedMapping: undefined,
          status: "ready",
          error: undefined,
        }
      }),
    )
  }

  function removeDraft(draftId: string) {
    setUploadQueue((prev) => prev.filter((item) => item.draftId !== draftId))
    if (mappingDraftId === draftId) {
      setMappingDraftId(null)
      setDialogOpen(false)
    }
  }

  async function deleteJob(jobId: string) {
    setError(null)
    try {
      const response = await fetch(`/api/alerts/uploads/${jobId}`, {
        method: "DELETE",
      })
      const payload = (await response.json().catch(() => ({}))) as { detail?: string }
      if (!response.ok) {
        throw new Error(String(payload.detail || `删除失败(${response.status})`))
      }
      if (expandedJobId === jobId) {
        setExpandedJobId(null)
      }
      if (currentJob?.job_id === jobId) {
        setCurrentJob(null)
        setAnalysisStatus(null)
        setApplyPayload(null)
      }
      await loadJobs()
      toast.success("任务已删除")
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "删除失败")
    }
  }

  function applyAgentInstruction() {
    if (!agentInstruction.trim()) {
      toast.error("请输入指令")
      return
    }
    toast.message("Agent 指令已记录（MVP）", { description: agentInstruction })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>数据接入</CardTitle>
          <CardDescription>上传文件或通过 API 对接，进入映射与入库流程。</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Tabs defaultValue="file">
            <TabsList>
              <TabsTrigger value="file">文件上传</TabsTrigger>
              <TabsTrigger value="api">API 对接</TabsTrigger>
            </TabsList>
            <TabsContent value="file" className="flex flex-col gap-3">
              <Input
                id="alert-upload-file"
                type="file"
                className="hidden"
                accept=".csv,text/csv"
                multiple
                onChange={(event) => {
                  const files = Array.from(event.target.files || [])
                  enqueueFiles(files)
                  event.currentTarget.value = ""
                }}
              />
              <div
                className={`rounded-lg border-2 border-dashed p-8 text-center transition-colors ${dragging ? "border-primary" : "border-border"} hover:border-primary`}
                onDragOver={(event) => {
                  event.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault()
                  setDragging(false)
                  enqueueFiles(Array.from(event.dataTransfer.files || []))
                }}
              >
                <p className="text-sm text-muted-foreground">
                  拖拽 CSV 到这里，或{" "}
                  <label htmlFor="alert-upload-file" className="cursor-pointer text-primary underline-offset-4 hover:underline">
                    点击上传
                  </label>
                </p>
                <p className="mt-2 text-xs text-muted-foreground">
                  {uploadQueue.length > 0 ? `当前队列 ${uploadQueue.length} 个文件` : "尚未选择文件"}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={ingestReadyDrafts} disabled={runningApply || uploadQueue.filter((item) => item.status === "ready").length === 0}>
                  {runningApply ? "入库中..." : "批量入库"}
                </Button>
                <Button variant="outline" onClick={triggerAnalyze} disabled={!currentJob?.job_id || runningAnalyze}>
                  {runningAnalyze ? "触发中..." : "触发分析"}
                </Button>
                <Button variant="outline" onClick={() => setUploadQueue([])} disabled={uploadQueue.length === 0 || runningApply}>
                  清空队列
                </Button>
              </div>
              <Card size="sm">
                <CardHeader>
                  <CardTitle className="text-sm">上传队列</CardTitle>
                  <CardDescription>每个文件独立选择模板；没有模板时可点击“生成模板”。</CardDescription>
                </CardHeader>
                <CardContent>
                  {uploadQueue.length === 0 ? (
                    <p className="text-sm text-muted-foreground">暂无待处理文件。</p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>文件</TableHead>
                          <TableHead>模板</TableHead>
                          <TableHead>状态</TableHead>
                          <TableHead>操作</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {uploadQueue.map((draft) => (
                          <TableRow key={draft.draftId}>
                            <TableCell className="text-sm">{draft.file.name}</TableCell>
                            <TableCell>
                              <Select value={draft.templateId || "__none__"} onValueChange={(value) => updateDraftTemplate(draft.draftId, value === "__none__" ? "" : value)}>
                                <SelectTrigger className="w-[220px]">
                                  <SelectValue placeholder="选择模板" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="__none__">不选择模板</SelectItem>
                                  {templates.map((template) => (
                                    <SelectItem key={`draft-template-${template.template_id}`} value={template.template_id}>
                                      {template.template_name}
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                            </TableCell>
                            <TableCell>
                              <Badge variant={draftStatusVariant(draft.status)}>{draftStatusLabel(draft.status)}</Badge>
                              {draft.linkedJobId ? <span className="ml-2 text-xs text-muted-foreground">{draft.linkedJobId}</span> : null}
                            </TableCell>
                            <TableCell className="flex gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => previewDraftMapping(draft.draftId)}
                                disabled={uploading || draft.status === "processing"}
                              >
                                {uploading && mappingDraftId === draft.draftId ? "生成中..." : "生成模板"}
                              </Button>
                              <Button variant="ghost" size="sm" onClick={() => removeDraft(draft.draftId)} disabled={draft.status === "processing"}>
                                移除
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
              <Card size="sm">
                <CardHeader>
                  <CardTitle className="text-sm">映射模板</CardTitle>
                  <CardDescription>当前浏览器已保存 {templates.length} 个模板，可查看详情与删除。</CardDescription>
                </CardHeader>
                <CardContent>
                  {templates.length === 0 ? (
                    <p className="text-sm text-muted-foreground">暂无模板，完成一次映射后可保存模板。</p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>模板名</TableHead>
                          <TableHead>创建时间</TableHead>
                          <TableHead>字段数</TableHead>
                          <TableHead>操作</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {templates.map((template) => (
                          <TableRow key={template.template_id}>
                            <TableCell>{template.template_name}</TableCell>
                            <TableCell>{formatTime(template.created_at)}</TableCell>
                            <TableCell>{Object.keys(template.mapping || {}).length}</TableCell>
                            <TableCell className="flex gap-2">
                              <Button variant="ghost" size="sm" onClick={() => openTemplateDetail(template)}>
                                查看
                              </Button>
                              <Button variant="ghost" size="sm" onClick={() => removeTemplate(template.template_id)}>
                                删除
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="api">
              <Alert>
                <AlertTitle>API 对接（预留）</AlertTitle>
                <AlertDescription>后续支持 API 拉取、Webhook、Syslog 等实时接入方式。</AlertDescription>
              </Alert>
            </TabsContent>
          </Tabs>
          {error ? (
            <Alert variant="destructive">
              <AlertTitle>操作失败</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>任务监控</CardTitle>
          <CardDescription>查看最近任务状态、进度与详细处理结果。</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {loadingJobs ? (
            <div className="flex flex-col gap-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : null}
          {!loadingJobs && jobs.length === 0 ? (
            <Alert>
              <AlertDescription>暂无任务，请先上传告警文件。</AlertDescription>
            </Alert>
          ) : null}
          {jobs.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>文件</TableHead>
                  <TableHead>总数</TableHead>
                  <TableHead>进度</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.map((job) => (
                  <Fragment key={job.job_id}>
                    <TableRow key={job.job_id}>
                      <TableCell className="font-mono text-xs">{job.job_id}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(job.status)}>{job.status}</Badge>
                      </TableCell>
                      <TableCell>{job.file_name || "-"}</TableCell>
                      <TableCell>{formatNumber(job.total_rows)}</TableCell>
                      <TableCell className="w-[220px]">
                        <Progress value={computeProgress(job)} />
                      </TableCell>
                      <TableCell className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={async () => {
                            setCurrentJob(job)
                            setExpandedJobId((prev) => (prev === job.job_id ? null : job.job_id))
                            await loadSample(job.job_id).catch(() => null)
                            await loadAnalysis(job.job_id).catch(() => null)
                          }}
                        >
                          查看
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => deleteJob(job.job_id)}>
                          删除
                        </Button>
                      </TableCell>
                    </TableRow>
                    {expandedJobId === job.job_id ? (
                      <TableRow>
                        <TableCell colSpan={6}>
                          <Card size="sm">
                            <CardHeader>
                              <CardTitle className="text-sm">任务详情</CardTitle>
                              <CardDescription>{`更新时间：${formatTime(job.updated_at)}`}</CardDescription>
                            </CardHeader>
                            <CardContent className="flex flex-col gap-3">
                              <div className="flex flex-wrap gap-2">
                                <Badge variant="outline">mapped={formatNumber(job.mapped_rows)}</Badge>
                                <Badge variant="outline">unmapped={formatNumber(job.unmapped_rows)}</Badge>
                                <Badge variant="outline">pending={formatNumber(job.pending_rows)}</Badge>
                                <Badge variant="outline">error={formatNumber(job.error_rows)}</Badge>
                              </div>
                              {analysisStatus?.run?.summary ? (
                                <Alert>
                                  <AlertTitle>分析摘要</AlertTitle>
                                  <AlertDescription>{analysisStatus.run.summary}</AlertDescription>
                                </Alert>
                              ) : null}
                              {applyPayload?.apply_result ? (
                                <Alert>
                                  <AlertTitle>入库结果</AlertTitle>
                                  <AlertDescription>
                                    processed={formatNumber(applyPayload.apply_result.processed)} mapped=
                                    {formatNumber(applyPayload.apply_result.mapped)} unmapped=
                                    {formatNumber(applyPayload.apply_result.unmapped)}
                                  </AlertDescription>
                                </Alert>
                              ) : null}
                            </CardContent>
                          </Card>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          ) : null}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent
          style={{ width: "96vw", maxWidth: "1600px" }}
          className="sm:max-w-none max-h-[92vh] overflow-y-auto"
        >
          <DialogHeader>
            <DialogTitle>映射配置</DialogTitle>
            <DialogDescription>确认字段映射后应用到当前文件，随后可在队列里批量入库。</DialogDescription>
          </DialogHeader>
          {mapBootstrap?.suggested_mapping && Object.keys(mapBootstrap.suggested_mapping).length > 0 ? (
            <Alert>
              <AlertTitle>已完成首轮自动映射</AlertTitle>
              <AlertDescription>
                已自动识别 {Object.keys(mapBootstrap.suggested_mapping).length} 个字段映射，你可以直接入库或在下方继续微调。
              </AlertDescription>
            </Alert>
          ) : null}
          <Card size="sm">
            <CardHeader>
              <CardTitle className="text-sm">目标映射样板（Agent 参考）</CardTitle>
              <CardDescription>Agent 会优先参考该样板做首轮映射，你可再微调。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>目标字段</TableHead>
                    <TableHead>说明</TableHead>
                    <TableHead>示例值</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(mapBootstrap?.target_schema_template?.fields || DEFAULT_TARGET_SCHEMA_TEMPLATE.fields || []).map((item) => (
                    <TableRow key={`target-schema-${item.name}`}>
                      <TableCell>
                        {item.name}
                        {item.required ? <Badge className="ml-2" variant="outline">必填</Badge> : null}
                      </TableCell>
                      <TableCell>{item.description || "-"}</TableCell>
                      <TableCell className="font-mono text-xs">{item.example || "-"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {(mapBootstrap?.target_schema_template?.mapping_principles || DEFAULT_TARGET_SCHEMA_TEMPLATE.mapping_principles || [])
                .length > 0 ? (
                <Alert>
                  <AlertTitle>映射原则</AlertTitle>
                  <AlertDescription>
                    {(mapBootstrap?.target_schema_template?.mapping_principles ||
                      DEFAULT_TARGET_SCHEMA_TEMPLATE.mapping_principles ||
                      []
                    ).join("；")}
                  </AlertDescription>
                </Alert>
              ) : null}
            </CardContent>
          </Card>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(420px,1fr)_40px_minmax(420px,1fr)]">
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Source Data</CardTitle>
              </CardHeader>
              <CardContent>
                {loadingSample ? (
                  <div className="flex flex-col gap-2">
                    <Skeleton className="h-20 w-full" />
                    <Skeleton className="h-20 w-full" />
                  </div>
                ) : (
                  <ScrollArea className="h-72 rounded-md border p-2">
                    <div className="flex flex-col gap-2">
                      {sampleRows.map((row, index) => (
                        <pre key={`sample-${index}`} className="overflow-x-auto rounded bg-muted p-2 text-xs">
                          {JSON.stringify(row, null, 2)}
                        </pre>
                      ))}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
            <div className="flex items-center justify-center">
              <ArrowRight />
            </div>
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">Target Mapping</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-72 rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>源字段</TableHead>
                        <TableHead>目标字段</TableHead>
                        <TableHead>标记</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {mappingRows.map((row, index) => (
                        <TableRow key={`${row.sourceField}-${index}`}>
                          <TableCell>{row.sourceField}</TableCell>
                          <TableCell>
                              <Select
                                value={row.targetField}
                                onValueChange={(value) => {
                                  setMappingRows((prev) =>
                                    prev.map((item, i) => (i === index ? { ...item, targetField: value, auto: false } : item)),
                                  )
                                }}
                              >
                              <SelectTrigger className="w-full min-w-[180px]">
                                <SelectValue placeholder="选择目标字段" />
                              </SelectTrigger>
                              <SelectContent>
                                {TARGET_FIELDS.map((field) => (
                                  <SelectItem key={field} value={field}>
                                    {field}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </TableCell>
                          <TableCell>{row.auto ? <Wand2 className="text-muted-foreground" /> : null}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
          <Card size="sm">
            <CardHeader>
              <CardTitle className="text-sm">Agent 交互</CardTitle>
              <CardDescription>示例：把 src_ip 换成 attacker_host，并把时间戳格式化为 yyyy-mm-dd。</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              <Textarea
                value={agentInstruction}
                onChange={(event) => setAgentInstruction(event.target.value)}
                placeholder="Agent，帮我调整映射规则..."
              />
              <div className="flex gap-2">
                <Button variant="outline" onClick={applyAgentInstruction}>
                  应用指令
                </Button>
              </div>
            </CardContent>
          </Card>
          <DialogFooter>
            <div className="flex w-full items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Input
                  value={templateName}
                  onChange={(event) => setTemplateName(event.target.value)}
                  placeholder="模板名称，例如 Nginx_Standard_Log"
                />
                <Button variant="outline" onClick={saveTemplate}>
                  保存模板
                </Button>
              </div>
              <Button onClick={applyMappingToDraft} disabled={mappingRows.length === 0}>
                应用到当前文件
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={templateDialogOpen} onOpenChange={setTemplateDialogOpen}>
        <DialogContent className="w-[95vw] max-w-[900px]">
          <DialogHeader>
            <DialogTitle>{selectedTemplate?.template_name || "模板详情"}</DialogTitle>
            <DialogDescription>
              {selectedTemplate ? `创建时间：${formatTime(selectedTemplate.created_at)}` : "查看已保存模板映射"}
            </DialogDescription>
          </DialogHeader>
          <div className="max-h-[60vh] overflow-y-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>源字段</TableHead>
                  <TableHead>目标字段</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {selectedTemplate
                  ? Object.entries(selectedTemplate.mapping || {}).map(([source, target]) => (
                      <TableRow key={`${selectedTemplate.template_id}-${source}`}>
                        <TableCell>{source}</TableCell>
                        <TableCell>{target || "-"}</TableCell>
                      </TableRow>
                    ))
                  : null}
              </TableBody>
            </Table>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
