import { useEffect, useState } from "react";
import api from "../services/api";
import type { Asset } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

const RESULT_COLORS: Record<string, string> = {
  "URGENT MIGRATION": "text-red-400",
  "PLAN MIGRATION": "text-orange-400",
  MONITOR: "text-yellow-400",
  "LOW PRIORITY": "text-emerald-400",
};

export default function MoscaPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [x, setX] = useState(5);
  const [y, setY] = useState(1.5);
  const [z, setZ] = useState(10);
  const [simResult, setSimResult] = useState<any>(null);

  useEffect(() => {
    if (!scanId) return;
    api.get("/assets", { params: { scan_id: scanId } }).then((res) => setAssets(res.data));
  }, [scanId]);

  function selectAsset(a: Asset) {
    setSelected(a);
    setSimResult(a.mosca);
    if (a.mosca) {
      setX(a.mosca.x_data_lifetime_years);
      setY(a.mosca.y_migration_time_years);
      setZ(a.mosca.z_threat_horizon_years);
    }
  }

  async function recalculate() {
    if (!selected) return;
    const res = await api.post("/mosca/simulate", {
      asset_id: selected.id,
      x_data_lifetime_years: x,
      y_migration_time_years: y,
      z_threat_horizon_years: z,
    });
    setSimResult(res.data);
  }

  const withMosca = assets.filter((a) => a.mosca);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Mosca Analysis</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>
      <p className="text-xs text-slate-500">
        X (data lifetime) + Y (migration time) vs Z (threat horizon). If X+Y exceeds Z, migration should be prioritized.
        The threat horizon is a configurable assumption — ECDAT does not claim a quantum computer will arrive by a specific year.
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card lg:col-span-1 space-y-2 max-h-[500px] overflow-y-auto">
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Assets</h2>
          {withMosca.map((a) => (
            <button
              key={a.id}
              onClick={() => selectAsset(a)}
              className={`block w-full text-left px-3 py-2 rounded text-xs ${
                selected?.id === a.id ? "bg-sky-950 text-sky-300" : "hover:bg-slate-800 text-slate-400"
              }`}
            >
              <div className="font-medium">{a.algorithm_name}</div>
              <div className={RESULT_COLORS[a.mosca!.result]}>{a.mosca!.result}</div>
            </button>
          ))}
        </div>

        <div className="card lg:col-span-2 space-y-4">
          {!selected ? (
            <div className="text-slate-400 text-sm">Select an asset to explore/recalculate its Mosca analysis.</div>
          ) : (
            <>
              <h2 className="text-sm font-semibold text-slate-300">{selected.algorithm_name}</h2>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">X: Data Lifetime (years)</label>
                  <input type="number" className="input" value={x} onChange={(e) => setX(Number(e.target.value))} />
                </div>
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Y: Migration Time (years)</label>
                  <input type="number" className="input" value={y} onChange={(e) => setY(Number(e.target.value))} />
                </div>
                <div>
                  <label className="text-xs text-slate-400 block mb-1">Z: Threat Horizon (years)</label>
                  <input type="number" className="input" value={z} onChange={(e) => setZ(Number(e.target.value))} />
                </div>
              </div>
              <button className="btn-primary" onClick={recalculate}>
                Recalculate
              </button>

              {simResult && (
                <div className="border-t border-slate-800 pt-4 space-y-2">
                  <div className="text-2xl font-bold">
                    X + Y = {simResult.x_plus_y}y{" "}
                    <span className="text-sm text-slate-500">vs Z = {simResult.z_threat_horizon_years}y</span>
                  </div>
                  <div className={`text-lg font-semibold ${RESULT_COLORS[simResult.result]}`}>{simResult.result}</div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
