import { useEffect, useState } from "react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, Legend } from "recharts";
import api from "../services/api";
import type { ScanDriftResponse } from "../types";

export default function PostureDriftPage() {
  const [data, setData] = useState<ScanDriftResponse | null>(null);

  useEffect(() => {
    // No selector – just use the most recent target as backend defaults
    api.get("/dashboard/drift").then((res) => setData(res.data));
  }, []);

  if (!data) {
    return <div className="text-slate-400">Loading posture drift data...</div>;
  }

  const chartData = data.history.map((h) => ({
    timestamp: new Date(h.timestamp).toLocaleDateString(),
    vulnerable: h.vulnerable_artefacts_count,
    pqc: h.pqc_adoption_percentage,
  }));

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-100">Posture Drift</h1>
      <ResponsiveContainer width="100%" height={320}>
        <LineChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="timestamp" tick={{ fill: "#94a3b8", fontSize: 11 }} />
          <YAxis yAxisId="left" label={{ value: "Vuln Count", angle: -90, position: "insideLeft" }} tick={{ fill: "#94a3b8", fontSize: 11 }} />
          <YAxis yAxisId="right" orientation="right" label={{ value: "% PQC", angle: -90, position: "insideRight" }} tick={{ fill: "#94a3b8", fontSize: 11 }} />
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
          <Legend />
          <Line yAxisId="left" type="monotone" dataKey="vulnerable" name="Vulnerable" stroke="#ef4444" />
          <Line yAxisId="right" type="monotone" dataKey="pqc" name="PQC %" stroke="#22c55e" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
