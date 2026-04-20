import Link from "next/link";
import { getJson } from "../../lib/api";

export default async function AssetsPage() {
  let items: any[] = [];
  try {
    const response = await getJson("/api/assets");
    items = response.items || [];
  } catch {
    items = [];
  }

  return (
    <section>
      <h1 className="title">资产清单</h1>
      {items.length === 0 ? <p className="meta">暂无资产</p> : null}
      {items.map((item) => (
        <div className="card" key={item.asset_id}>
          <p className="meta">
            <Link href={`/assets/${item.asset_id}`}>{item.asset_id}</Link>
          </p>
          <p className="meta">{item.asset_name}</p>
          <p className="meta">
            {item.public_ip || "-"} · {item.domain || "-"}
          </p>
        </div>
      ))}
    </section>
  );
}

