import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../services/api";
import type { Asset } from "../types";
import SeverityBadge from "../components/SeverityBadge";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

export default function InventoryPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    const params: any = { scan_id: scanId };
    if (severityFilter) params.severity = severityFilter;
    api.get("/assets", { params }).then((res) => setAssets(res.data)).finally(() => setLoading(false));
  }, [scanId, severityFilter]);

  const filtered = assets.filter(
    (a) =>
      !search ||
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      (a.algorithm_name || "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Cryptographic Inventory</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      <div className="flex gap-3 flex-wrap">
        <input className="input max-w-xs" placeholder="Search algorithm or name..." value={search} onChange={(e) => setSearch(e.target.value)} />
        <select className="input w-40" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {loading ? (
        <div className="text-slate-400">Loading...</div>
      ) : filtered.length === 0 ? (
        <div className="card text-slate-400 text-sm">No assets found for this scan/filter.</div>
      ) : (
        <div className="card p-0 overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Purpose</th>
                <th>Key Size</th>
                <th>Location</th>
                <th>Business Asset</th>
                <th>Risk</th>
                <th>Confidence</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => (
                <tr key={a.id}>
                                  <td className="font-medium text-slate-200">{a.algorithm_name}{a.provenance_risk === "ai_suspected" && (<span className="ml-2 bg-orange-600 text-orange-100 px-2 py-0.5 rounded-sm text-xs">AI-suspected crypto</span>)}</td>
                  <td className="text-xs text-slate-400">{a.purpose || "—"}</td>
                  <td>{a.key_size || "—"}</td>
                  <td className="font-mono text-xs text-slate-500 max-w-xs truncate" title={a.location}>
                    {a.location}
                  </td>
                  <td className="text-xs">{a.business_asset || "—"}</td>
                  <td>{a.risk ? <SeverityBadge severity={a.risk.severity} /> : "—"}</td>
                  <td className="text-xs text-slate-500">{(a.confidence * 100).toFixed(0)}%</td>
                  <td>
                    <Link to={`/assets/${a.id}`} className="text-sky-400 hover:underline text-xs">
                      Details
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
