import { getJson } from "../../../lib/api";

export default async function CaseDetailPage({ params }: { params: { caseId: string } }) {
  let data: any | null = null;
  try {
    data = await getJson(`/api/cases/${params.caseId}`);
  } catch {
    data = null;
  }

  if (!data?.case) {
    return (
      <section>
        <h1 className="title">案件详情</h1>
        <p className="meta">案件不存在或 API 不可用</p>
      </section>
    );
  }

  return (
    <section>
      <h1 className="title">{data.case.title}</h1>
      <div className="card">
        <h2>攻击者画像</h2>
        {(data.actors || []).length === 0 ? <p className="meta">暂无画像</p> : null}
        {(data.actors || []).map((actor: any) => (
          <p key={actor.case_actor_id} className="meta">
            {actor.label} · {actor.current_stage} · confidence={actor.profile_confidence}
          </p>
        ))}
      </div>
      <div className="card">
        <h2>攻击过程（时间线）</h2>
        {(data.timeline || []).length === 0 ? <p className="meta">暂无时间线</p> : null}
        {(data.timeline || []).map((event: any) => (
          <p key={event.timeline_event_id} className="meta">
            {event.occurred_at} · {event.stage} · {event.title}
          </p>
        ))}
      </div>
      <div className="card">
        <h2>证据链解释</h2>
        {(data.link_explanations || []).length === 0 ? <p className="meta">暂无关联解释</p> : null}
        {(data.link_explanations || []).slice(0, 10).map((item: any) => (
          <p key={item.decision_id} className="meta">
            {item.alert_id} · score={item.link_confidence} · {item.reason_summary}
          </p>
        ))}
      </div>
    </section>
  );
}

