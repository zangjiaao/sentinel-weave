import Link from "next/link";
import { getJson } from "../../lib/api";

export default async function CasesPage() {
  let items: any[] = [];
  try {
    const response = await getJson("/api/cases");
    items = response.items || [];
  } catch {
    items = [];
  }

  return (
    <section>
      <h1 className="title">案件列表</h1>
      {items.length === 0 ? <p className="meta">暂无案件</p> : null}
      {items.map((item) => (
        <div className="card" key={item.case_id}>
          <p className="meta">
            <Link href={`/cases/${item.case_id}`}>{item.case_id}</Link>
          </p>
          <p className="meta">{item.title}</p>
          <p className="meta">
            {item.overall_severity} · {item.current_stage} · {item.status}
          </p>
        </div>
      ))}
    </section>
  );
}

