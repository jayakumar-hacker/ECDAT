import { useEffect, useState } from "react";
import api from "../services/api";
import type { MigrationPlan } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

export default function MigrationSimulatorPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [plans, setPlans] = useState<MigrationPlan[]>([]);
  const [current, setCurrent] = useState("RSA-2048");
  const [proposed, setProposed] = useState("ML-KEM");
  const [simResult, setSimResult] = useState<any>(null);
  const [simLoading, setSimLoading] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    api.get("/migration-plans", { params: { scan_id: scanId } }).then((res) => setPlans(res.data));
  }, [scanId]);

  async function runSimulation() {
    setSimLoading(true);
    try {
      const res = await api.post("/migration-plans/simulate", { current_algorithm: current, proposed_algorithm: proposed });
      setSimResult(res.data);
    } finally {
      setSimLoading(false);
    }
  }

  const priorityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Migration Simulator</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      <div className="card space-y-4 max-w-2xl">
        <h2 className="text-sm font-semibold text-slate-300">Compare Current vs Proposed</h2>
        <div className="flex gap-3 items-end flex-wrap">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Current Algorithm</label>
            <input className="input" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Proposed Algorithm</label>
            <input className="input" value={proposed} onChange={(e) => setProposed(e.target.value)} />
          </div>
          <button className="btn-primary" onClick={runSimulation} disabled={simLoading}>
            {simLoading ? "Simulating..." : "Simulate"}
          </button>
        </div>

        {simResult && (
          <div className="border-t border-slate-800 pt-4 space-y-2 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <div className="text-slate-500">Security</div>
              <div>{simResult.comparison.security}</div>
              <div className="text-slate-500">Quantum Resistance</div>
              <div>{simResult.comparison.quantum_resistance}</div>
              <div className="text-slate-500">Compatibility</div>
              <div>{simResult.comparison.compatibility}</div>
              <div className="text-slate-500">Latency</div>
              <div className="text-amber-400">{simResult.comparison.latency}</div>
              <div className="text-slate-500">Computational Overhead</div>
              <div className="text-amber-400">{simResult.comparison.computational_overhead}</div>
              <div className="text-slate-500">Migration Complexity</div>
              <div>{simResult.comparison.migration_complexity}</div>
              <div className="text-slate-500">Dependency Impact</div>
              <div className="text-amber-400">{simResult.comparison.dependency_impact}</div>
            </div>
            <p className="text-xs text-slate-500 pt-2">
              Fields marked "Not measured" have no fabricated benchmark data — supply real measurements to override.
            </p>
          </div>
        )}
      </div>

      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Migration Priorities (this scan)</h2>
        <div className="space-y-2">
          {priorityOrder.map((prio) => {
            const group = plans.filter((p) => p.priority === prio);
            if (group.length === 0) return null;
            return (
              <div key={prio}>
                <div className={`text-xs font-semibold mb-1 badge-${prio} inline-block px-2 py-0.5 rounded`}>{prio} ({group.length})</div>
                {group.map((p) => (
                  <div key={p.id} className="card mt-2">
                    <div className="flex justify-between">
                      <span className="font-medium text-slate-200">{p.algorithm}</span>
                      <span className="text-xs text-slate-500">Risk before: {p.risk_before}</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">{p.rationale}</div>
                    <div className="text-xs text-emerald-400 mt-1">→ {p.replacement}</div>
                    {p.blockers.length > 0 && (
                      <div className="text-xs text-amber-400 mt-1">Blockers: {p.blockers.join("; ")}</div>
                    )}
                    <div className="text-xs text-slate-500 mt-1">Risk after: {p.risk_after_estimate}</div>
                  </div>
                ))}
              </div>
            );
          })}
          {plans.length === 0 && <div className="card text-slate-400 text-sm">No migration plans for this scan yet.</div>}
        </div>
      </div>
    </div>
  );
}
