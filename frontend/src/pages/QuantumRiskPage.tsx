import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from "recharts";
import api from "../services/api";
import type { Asset } from "../types";
import SeverityBadge from "../components/SeverityBadge";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

const SEVERITY_COLORS: Record<string, string> = { LOW: "#22c55e", MEDIUM: "#eab308", HIGH: "#f97316", CRITICAL: "#ef4444" };

export default function QuantumRiskPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get("/assets", { params: { scan_id: scanId } }).then((res) => setAssets(res.data));
  }, [scanId]);

  const ranked = [...assets]
    .filter((a) => a.risk)
    .sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0));

  const chartData = ranked.slice(0, 15).map((a) => ({
    name: `${a.algorithm_name}`,
    score: a.risk!.score,
    severity: a.risk!.severity,
  }));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Quantum Risk</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>
      <p className="text-xs text-slate-500">
        ECDAT risk scoring model (0–100, documented in docs/risk-model.md) — not an official NIST/CVSS score.
      </p>

      <div className="card">
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Top Risk Scores</h2>
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={chartData} layout="vertical" margin={{ left: 40 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis type="number" domain={[0, 100]} tick={{ fill: "#94a3b8", fontSize: 11 }} />
            <YAxis type="category" dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} width={120} />
            <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
            <Bar dataKey="score">
              {chartData.map((d, i) => (
                <Cell key={i} fill={SEVERITY_COLORS[d.severity]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card p-0 overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Location</th>
              <th>Score</th>
              <th>Severity</th>
              <th>Top Factor</th>
            </tr>
          </thead>
          <tbody>
            {ranked.map((a) => (
              <tr key={a.id}>
                <td className="font-medium">{a.algorithm_name}</td>
                <td className="font-mono text-xs text-slate-500 max-w-xs truncate">{a.location}</td>
                <td>{a.risk!.score}</td>
                <td><SeverityBadge severity={a.risk!.severity} /></td>
                <td className="text-xs text-slate-400">
                  {[...a.risk!.factors].sort((x, y) => y.impact - x.impact)[0]?.name.replace(/_/g, " ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
