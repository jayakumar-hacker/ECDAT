import { useEffect, useState } from "react";
import api from "../services/api";
import type { CbomComponent } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

export default function CbomExplorerPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [components, setComponents] = useState<CbomComponent[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    api.get("/cbom", { params: { scan_id: scanId } }).then((res) => setComponents(res.data.components)).finally(() => setLoading(false));
  }, [scanId]);

  function download(format: "json" | "csv") {
    const token = localStorage.getItem("ecdat_token");
    const url = `/api/cbom/export?scan_id=${scanId}&format=${format}`;
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.blob())
      .then((blob) => {
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `cbom.${format}`;
        link.click();
      });
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">CBOM Explorer</h1>
        <div className="flex gap-2 items-center">
          <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
          <button className="btn-secondary" onClick={() => download("json")}>
            Export JSON
          </button>
          <button className="btn-secondary" onClick={() => download("csv")}>
            Export CSV
          </button>
        </div>
      </div>
      <p className="text-xs text-slate-500">
        Simplified schema inspired by CycloneDX CBOM concepts — see docs/cbom.md. Not a conformant CycloneDX document.
      </p>

      {loading ? (
        <div className="text-slate-400">Loading...</div>
      ) : (
        <div className="card p-0 overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Type</th>
                <th>Purpose</th>
                <th>Key Size</th>
                <th>Component</th>
                <th>Business Asset</th>
                <th>Quantum Security</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {components.map((c) => (
                <tr key={c.id}>
                  <td className="font-medium text-slate-200">{c.algorithm}</td>
                  <td className="text-xs text-slate-400">{c.type}</td>
                  <td className="text-xs text-slate-400">{c.purpose || "—"}</td>
                  <td>{c.key_size || "—"}</td>
                  <td className="text-xs">{c.component || "—"}</td>
                  <td className="text-xs">{c.business_asset || "—"}</td>
                  <td className="text-xs">{c.quantum_security}</td>
                  <td>{c.risk_score ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
