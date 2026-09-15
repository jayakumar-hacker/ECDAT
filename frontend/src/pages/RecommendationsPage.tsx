import { useEffect, useState } from "react";
import api from "../services/api";
import type { Recommendation } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

const PRIORITY_COLORS: Record<string, string> = {
  HIGH: "badge-HIGH",
  MEDIUM: "badge-MEDIUM",
  LOW: "badge-LOW",
};

export default function RecommendationsPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [recs, setRecs] = useState<(Recommendation & { asset_name: string })[]>([]);
  const [priority, setPriority] = useState("");

  useEffect(() => {
    if (!scanId) return;
    const params: any = { scan_id: scanId };
    if (priority) params.priority = priority;
    api.get("/recommendations", { params }).then((res) => setRecs(res.data));
  }, [scanId, priority]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">PQC Recommendations</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>
      <div className="flex gap-2">
        {["", "HIGH", "MEDIUM", "LOW"].map((p) => (
          <button
            key={p}
            onClick={() => setPriority(p)}
            className={`text-xs px-3 py-1 rounded ${priority === p ? "bg-sky-700 text-white" : "bg-slate-800 text-slate-400"}`}
          >
            {p || "All"}
          </button>
        ))}
      </div>

      <div className="grid gap-3">
        {recs.map((r) => (
          <div key={r.id} className="card">
            <div className="flex justify-between items-start mb-2">
              <div>
                <span className="text-slate-400">{r.current_algorithm}</span>
                <span className="mx-2 text-slate-600">→</span>
                <span className="text-emerald-400 font-semibold">{r.recommended_algorithm}</span>
              </div>
              <span className={`badge-${r.priority} text-xs px-2 py-0.5 rounded font-semibold`}>{r.priority}</span>
            </div>
            {r.hybrid_option && <div className="text-xs text-slate-500 mb-1">Hybrid: {r.hybrid_option}</div>}
            <p className="text-xs text-slate-400 mb-1">{r.reason}</p>
            <div className="flex gap-4 text-xs text-slate-500">
              <span>Category: {r.category}</span>
              <span>Complexity: {r.migration_complexity}</span>
              <span>Confidence: {(r.confidence * 100).toFixed(0)}%</span>
            </div>
          </div>
        ))}
        {recs.length === 0 && <div className="card text-slate-400 text-sm">No recommendations for this filter.</div>}
      </div>
    </div>
  );
}
