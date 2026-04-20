"use client";

import { useMemo, useState } from "react";

type FilterState =
  | { type: "none"; value: "" }
  | { type: "attacker"; value: string }
  | { type: "target"; value: string };

function formatTime(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString("zh-CN", { hour12: false });
}

export default function CaseDetailClient({ data }: { data: any }) {
  const caseItem = data.case;
  const attackerTargetMap = data.attacker_target_map || [];
  const attackAlertTimeline = data.attack_alert_timeline || [];
  const behavior = data.attack_behavior_analysis || {};
  const stageProgression = behavior.stage_progression || [];

  const [filter, setFilter] = useState<FilterState>({ type: "none", value: "" });

  const targetSummaryMap = new Map<
    string,
    {
      key: string;
      target: string;
      asset_id: string | null;
      dst_ip: string | null;
      alert_count: number;
      high_signal_count: number;
    }
  >();
  for (const attacker of attackerTargetMap) {
    for (const target of attacker.targets || []) {
      const targetKey = `${target.asset_id || ""}|${target.dst_ip || ""}`;
      const existed = targetSummaryMap.get(targetKey);
      if (!existed) {
        targetSummaryMap.set(targetKey, {
          key: targetKey,
          target: target.target || `${target.asset_id || "-"} / ${target.dst_ip || "-"}`,
          asset_id: target.asset_id || null,
          dst_ip: target.dst_ip || null,
          alert_count: Number(target.alert_count || 0),
          high_signal_count: Number(target.high_signal_count || 0),
        });
        continue;
      }
      existed.alert_count += Number(target.alert_count || 0);
      existed.high_signal_count += Number(target.high_signal_count || 0);
    }
  }
  const targetSummaries = Array.from(targetSummaryMap.values()).sort(
    (left, right) =>
      Number(right.high_signal_count || 0) - Number(left.high_signal_count || 0) ||
      Number(right.alert_count || 0) - Number(left.alert_count || 0) ||
      String(left.target).localeCompare(String(right.target)),
  );

  const filteredTimeline = useMemo(() => {
    if (filter.type === "none") {
      return attackAlertTimeline;
    }
    if (filter.type === "attacker") {
      return attackAlertTimeline.filter((row: any) => String(row.src_ip || "") === filter.value);
    }
    return attackAlertTimeline.filter(
      (row: any) => `${row.asset_id || ""}|${row.dst_ip || ""}` === filter.value,
    );
  }, [attackAlertTimeline, filter]);

  const activeFilterLabel =
    filter.type === "attacker"
      ? `攻击者：${filter.value}`
      : filter.type === "target"
        ? `目标资产：${filter.value}`
        : "全部告警";

  return (
    <section>
      <h1 className="title">{caseItem.title}</h1>
      <p className="meta">
        {caseItem.case_id} · severity={caseItem.overall_severity} · stage={caseItem.current_stage} · status=
        {caseItem.status}
      </p>

      <div className="card">
        <h2>攻击行为分析</h2>
        {behavior.summary ? <p className="meta">{behavior.summary}</p> : <p className="meta">暂无行为分析结果</p>}
        {(behavior.highlights || []).map((item: string) => (
          <p key={item} className="meta">
            - {item}
          </p>
        ))}
        <div className="subcard">
          <p className="meta">
            <strong>阶段推进分析</strong>
          </p>
          {stageProgression.length === 0 ? <p className="meta">暂无阶段推进信息</p> : null}
          {stageProgression.map((item: any) => (
            <p key={`${item.stage}-${item.first_seen_at || ""}`} className="meta">
              {item.stage} · alerts={item.alert_count} · first_seen={formatTime(item.first_seen_at)} · last_seen=
              {formatTime(item.last_seen_at)}
            </p>
          ))}
        </div>
      </div>

      <div className="detail-grid">
        <div className="card">
          <h2>攻击者</h2>
          {attackerTargetMap.length === 0 ? <p className="meta">暂无攻击者关联信息</p> : null}
          {attackerTargetMap.map((attacker: any) => {
            const active = filter.type === "attacker" && filter.value === attacker.attacker;
            return (
              <button
                key={attacker.attacker}
                type="button"
                className={`subcard selectable-card${active ? " active" : ""}`}
                onClick={() =>
                  setFilter((current) =>
                    current.type === "attacker" && current.value === attacker.attacker
                      ? { type: "none", value: "" }
                      : { type: "attacker", value: attacker.attacker },
                  )
                }
              >
                <p className="meta">
                  <strong>{attacker.attacker}</strong> · alerts={attacker.alert_count} · high_signal=
                  {attacker.high_signal_count}
                </p>
                <p className="meta">
                  stages={(attacker.stages || []).join(" → ") || "-"} · targets={(attacker.targets || []).length}
                </p>
                <p className="meta">
                  first_seen={formatTime(attacker.first_seen_at)} · last_seen={formatTime(attacker.last_seen_at)}
                </p>
              </button>
            );
          })}
        </div>

        <div className="card">
          <h2>目标资产</h2>
          {targetSummaries.length === 0 ? <p className="meta">暂无目标资产信息</p> : null}
          {targetSummaries.map((target) => {
            const active = filter.type === "target" && filter.value === target.key;
            return (
              <button
                key={target.key}
                type="button"
                className={`subcard selectable-card${active ? " active" : ""}`}
                onClick={() =>
                  setFilter((current) =>
                    current.type === "target" && current.value === target.key
                      ? { type: "none", value: "" }
                      : { type: "target", value: target.key },
                  )
                }
              >
                <p className="meta">
                  <strong>{target.asset_id || "-"}</strong> / {target.dst_ip || "-"}
                </p>
                <p className="meta">
                  alerts={target.alert_count} · high_signal={target.high_signal_count}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      <div className="card">
        <h2>攻击告警时间线（最新优先）</h2>
        <div className="timeline-filter-bar">
          <p className="meta">当前筛选：{activeFilterLabel}</p>
          {filter.type !== "none" ? (
            <button type="button" className="clear-filter-btn" onClick={() => setFilter({ type: "none", value: "" })}>
              清除筛选
            </button>
          ) : null}
        </div>
        {filteredTimeline.length === 0 ? <p className="meta">当前筛选条件下暂无告警时间线</p> : null}
        {filteredTimeline.length > 0 ? (
          <div className="table-wrap">
            <table className="timeline-table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>攻击IP</th>
                  <th>攻击类型</th>
                  <th>攻击描述</th>
                  <th>目标</th>
                </tr>
              </thead>
              <tbody>
                {filteredTimeline.map((row: any) => (
                  <tr key={row.alert_id}>
                    <td>{formatTime(row.occurred_at)}</td>
                    <td>{row.src_ip}</td>
                    <td>{row.attack_type}</td>
                    <td>{row.attack_description}</td>
                    <td>{row.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  );
}
