import { getJson } from "../../../lib/api";

export default async function AssetDetailPage({ params }: { params: { assetId: string } }) {
  let data: any | null = null;
  try {
    data = await getJson(`/api/assets/${params.assetId}`);
  } catch {
    data = null;
  }

  if (!data?.asset) {
    return (
      <section>
        <h1 className="title">资产详情</h1>
        <p className="meta">资产不存在或 API 不可用</p>
      </section>
    );
  }

  return (
    <section>
      <h1 className="title">{data.asset.asset_name}</h1>
      <div className="card">
        <h2>身份归并</h2>
        {(data.identities || []).length === 0 ? <p className="meta">暂无归并数据</p> : null}
        {(data.identities || []).map((item: any) => (
          <p key={item.identity_id} className="meta">
            {item.identity_type}: {item.identity_value}
          </p>
        ))}
      </div>
      <div className="card">
        <h2>关联案件</h2>
        {(data.cases || []).length === 0 ? <p className="meta">暂无关联案件</p> : null}
        {(data.cases || []).map((item: any) => (
          <p key={item.case_id} className="meta">
            {item.case_id} · {item.overall_severity} · {item.current_stage}
          </p>
        ))}
      </div>
    </section>
  );
}

