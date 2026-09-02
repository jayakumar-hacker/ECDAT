import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import api from "../services/api";
import StatCard from "../components/StatCard";
import type { DashboardData } from "../types";

const SEVERITY_COLORS: Record<string, string> = {
  LOW: "#22c55e",
  MEDIUM: "#eab308",
  HIGH: "#f97316",
  CRITICAL: "#ef4444",
};

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get("/dashboard")
      .then((res) => setData(res.data))
      .catch(() => setError("Failed to load dashboard data"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-slate-400">Loading dashboard...</div>;
  if (error) return <div className="text-red-400">{error}</div>;
  if (!data) return null;

  const severityData = Object.entries(data.risk_distribution).map(([name, value]) => ({ name, value }));
  const algoData = Object.entries(data.algorithm_distribution)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, value]) => ({ name, value }));
  const migrationData = Object.entries(data.migration_priority_distribution).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>

      {data.total_crypto_assets === 0 && (
        <div className="card border-sky-900 bg-sky-950/30 text-sky-300 text-sm">
          No scan data yet. Head to the <a href="/scan" className="underline">Scan</a> page and run the demo repository to populate this dashboard.
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Crypto Assets" value={data.total_crypto_assets} />
        <StatCard label="Quantum-Vulnerable" value={data.quantum_vulnerable_assets} tone="orange-400" />
        <StatCard label="Critical Risks" value={data.critical_risks} tone="red-400" />
        <StatCard label="High Risks" value={data.high_risks} tone="orange-400" />
        <StatCard label="Certificates" value={data.certificates_found} />
        <StatCard label="Crypto Libraries" value={data.crypto_libraries_found} />
        <StatCard label="Applications Scanned" value={data.applications_scanned} />
        <StatCard label="Scans Run" value={data.scans_run} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Risk Distribution</h2>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" outerRadius={80} label>
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#64748b"} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Migration Priority</h2>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={migrationData} dataKey="value" nameKey="name" outerRadius={80} label>
                {migrationData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#64748b"} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card lg:col-span-2">
          <h2 className="text-sm font-semibold text-slate-300 mb-3">Algorithm Distribution (Top 10)</h2>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={algoData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} angle={-30} textAnchor="end" height={70} />
              <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
              <Bar dataKey="value" fill="#38bdf8" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
