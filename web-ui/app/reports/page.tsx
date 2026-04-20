import { getJson } from "../../lib/api";

export default async function ReportsPage() {
  let items: any[] = [];
  try {
    const response = await getJson("/api/reports");
    items = response.items || [];
  } catch {
    items = [];
  }

  return (
    <section>
      <h1 className="title">报告</h1>
      <div className="card">
        <p className="meta">MVP 仅支持预览，不执行真实导出。</p>
      </div>
      {items.length === 0 ? <p className="meta">暂无报告草稿</p> : null}
      {items.map((item) => (
        <div key={item.report_id} className="card">
          <p className="meta">{item.report_id}</p>
          <p className="meta">
            {item.status} · case={item.case_id}
          </p>
          <p className="meta">{item.title}</p>
        </div>
      ))}
    </section>
  );
}

