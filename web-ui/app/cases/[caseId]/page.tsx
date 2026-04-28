import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { getJson } from "@/lib/api"

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

function formatFactor(value: unknown): string {
  if (typeof value === "string") {
    return value
  }
  if (value === null || value === undefined) {
    return "-"
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value)
  }
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export default async function CaseDetailPage({ params }: { params: Promise<{ caseId: string }> }) {
  const { caseId } = await params

  let data: any | null = null
  try {
    data = await getJson(`/api/cases/${caseId}`)
  } catch {
    data = null
  }

  if (!data?.case) {
    return (
      <section className="flex flex-col gap-4">
        <h1 className="text-2xl font-semibold">案件详情</h1>
        <Alert>
          <AlertTitle>无法加载案件</AlertTitle>
          <AlertDescription>案件不存在或 API 不可用。</AlertDescription>
        </Alert>
      </section>
    )
  }

  const caseItem = data.case
  const timeline = Array.isArray(data.attack_alert_timeline) ? data.attack_alert_timeline : []
  const behavior = data.attack_behavior_analysis || {}
  const judgement = data.agent_judgement || {}
  const actors = Array.isArray(data.actors) ? data.actors : []
  const targets = Array.isArray(data.targets) ? data.targets : []
  const links = Array.isArray(data.link_explanations) ? data.link_explanations : []
  const assessments = Array.isArray(data.assessments) ? data.assessments : []
  const confidenceSummary = judgement.link_confidence_summary || {}
  const latestAssessment = judgement.latest_assessment || null

  return (
    <section className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{caseItem.title}</CardTitle>
          <CardDescription>{caseItem.case_id}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge variant="outline">{caseItem.overall_severity}</Badge>
          <Badge variant="outline">{caseItem.current_stage}</Badge>
          <Badge variant="outline">{caseItem.status}</Badge>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>研判摘要</CardTitle>
          <CardDescription>Agent 当前证据链置信度与不确定性统计。</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline">total={confidenceSummary.total ?? 0}</Badge>
            <Badge variant="outline">high={confidenceSummary.high_confidence_count ?? 0}</Badge>
            <Badge variant="outline">medium={confidenceSummary.medium_confidence_count ?? 0}</Badge>
            <Badge variant="outline">low={confidenceSummary.low_confidence_count ?? 0}</Badge>
            <Badge variant="outline">avg={confidenceSummary.avg_confidence ?? "-"}</Badge>
            <Badge variant="outline">uncertainties={judgement.total_uncertainty_count ?? 0}</Badge>
          </div>
          {latestAssessment ? (
            <Alert>
              <AlertTitle>最新实体评估</AlertTitle>
              <AlertDescription>
                {latestAssessment.verdict || "-"} · confidence={latestAssessment.assessment_confidence ?? "-"} ·
                {latestAssessment.reason_summary || "-"}
              </AlertDescription>
            </Alert>
          ) : (
            <Alert>
              <AlertDescription>暂无实体评估摘要。</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>攻击行为分析</CardTitle>
          <CardDescription>{behavior.summary || "暂无行为分析结果"}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {(behavior.highlights || []).map((item: string) => (
            <Alert key={item}>
              <AlertDescription>{item}</AlertDescription>
            </Alert>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>攻击者画像</CardTitle>
          <CardDescription>当前案件关联的攻击者实体。</CardDescription>
        </CardHeader>
        <CardContent>
          {actors.length === 0 ? (
            <Alert>
              <AlertDescription>暂无攻击者画像。</AlertDescription>
            </Alert>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>标签</TableHead>
                  <TableHead>风险</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>阶段</TableHead>
                  <TableHead>置信度</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {actors.map((item: any) => (
                  <TableRow key={item.case_actor_id}>
                    <TableCell>{item.label || "-"}</TableCell>
                    <TableCell>{item.risk_level || "-"}</TableCell>
                    <TableCell>{item.status || "-"}</TableCell>
                    <TableCell>{item.current_stage || "-"}</TableCell>
                    <TableCell>{item.profile_confidence ?? "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>目标资产</CardTitle>
          <CardDescription>被攻击资产与相关告警统计。</CardDescription>
        </CardHeader>
        <CardContent>
          {targets.length === 0 ? (
            <Alert>
              <AlertDescription>暂无目标资产统计。</AlertDescription>
            </Alert>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>资产</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>告警数</TableHead>
                  <TableHead>高信号</TableHead>
                  <TableHead>阶段数</TableHead>
                  <TableHead>最近时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((item: any, index: number) => (
                  <TableRow key={`${item.asset_id || "na"}-${item.dst_ip || "na"}-${index}`}>
                    <TableCell>{item.asset_id || "-"}</TableCell>
                    <TableCell>{item.dst_ip || "-"}</TableCell>
                    <TableCell>{item.alert_count ?? 0}</TableCell>
                    <TableCell>{item.high_signal_count ?? 0}</TableCell>
                    <TableCell>{item.stage_count ?? 0}</TableCell>
                    <TableCell>{formatTime(item.last_seen_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>证据链解释</CardTitle>
          <CardDescription>告警与案件关联时的依据与不确定性。</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {links.length === 0 ? (
            <Alert>
              <AlertDescription>暂无证据链解释。</AlertDescription>
            </Alert>
          ) : (
            links.map((item: any) => (
              <Card key={item.decision_id} size="sm">
                <CardHeader>
                  <CardTitle className="text-sm">
                    {item.alert_id || "-"} · confidence={item.link_confidence ?? "-"}
                  </CardTitle>
                  <CardDescription>
                    {formatTime(item.occurred_at)} · {item.alert_stage || "-"} · {item.alert_title || "-"}
                  </CardDescription>
                </CardHeader>
                <CardContent className="flex flex-col gap-2">
                  <Alert>
                    <AlertDescription>{item.reason_summary || "-"}</AlertDescription>
                  </Alert>
                  <div className="flex flex-wrap gap-2">
                    {(item.positive_factors || []).map((factor: unknown, index: number) => (
                      <Badge key={`p-${item.decision_id}-${index}-${formatFactor(factor)}`} variant="outline">
                        + {formatFactor(factor)}
                      </Badge>
                    ))}
                    {(item.negative_factors || []).map((factor: unknown, index: number) => (
                      <Badge key={`n-${item.decision_id}-${index}-${formatFactor(factor)}`} variant="outline">
                        - {formatFactor(factor)}
                      </Badge>
                    ))}
                    {(item.uncertainties || []).map((factor: unknown, index: number) => (
                      <Badge key={`u-${item.decision_id}-${index}-${formatFactor(factor)}`} variant="outline">
                        ? {formatFactor(factor)}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>实体评估</CardTitle>
          <CardDescription>对攻击实体的阶段性判断与证据支撑。</CardDescription>
        </CardHeader>
        <CardContent>
          {assessments.length === 0 ? (
            <Alert>
              <AlertDescription>暂无实体评估记录。</AlertDescription>
            </Alert>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>结论</TableHead>
                  <TableHead>风险</TableHead>
                  <TableHead>阶段</TableHead>
                  <TableHead>置信度</TableHead>
                  <TableHead>证据数</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assessments.map((item: any) => (
                  <TableRow key={item.assessment_id}>
                    <TableCell>{formatTime(item.occurred_at)}</TableCell>
                    <TableCell>{item.verdict || "-"}</TableCell>
                    <TableCell>{item.risk_level || "-"}</TableCell>
                    <TableCell>{item.current_stage || "-"}</TableCell>
                    <TableCell>{item.assessment_confidence ?? "-"}</TableCell>
                    <TableCell>{Array.isArray(item.supporting_alert_ids) ? item.supporting_alert_ids.length : 0}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>时间线</CardTitle>
          <CardDescription>按告警还原攻击事件（最新优先）。</CardDescription>
        </CardHeader>
        <CardContent>
          {timeline.length === 0 ? (
            <Alert>
              <AlertDescription>暂无时间线数据。</AlertDescription>
            </Alert>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>攻击IP</TableHead>
                  <TableHead>攻击类型</TableHead>
                  <TableHead>攻击描述</TableHead>
                  <TableHead>目标</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {timeline.map((row: any) => (
                  <TableRow key={row.alert_id}>
                    <TableCell>{formatTime(row.occurred_at)}</TableCell>
                    <TableCell>{row.src_ip || "-"}</TableCell>
                    <TableCell>{row.attack_type || row.attack_stage || "-"}</TableCell>
                    <TableCell>{row.attack_description || row.title || "-"}</TableCell>
                    <TableCell>{row.target || row.asset_id || row.dst_ip || "-"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </section>
  )
}
