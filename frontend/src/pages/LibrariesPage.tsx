import { useEffect, useState } from "react";
import api from "../services/api";
import type { Library } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

export default function LibrariesPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [libs, setLibs] = useState<Library[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get("/libraries", { params: { scan_id: scanId } }).then((res) => setLibs(res.data));
  }, [scanId]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Crypto Libraries</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      <div className="card p-0 overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Ecosystem</th>
              <th>Known Algorithms</th>
              <th>Source</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {libs.map((l) => (
              <tr key={l.id}>
                <td className="font-medium">{l.name}</td>
                <td className="text-xs text-slate-400">{l.version}</td>
                <td className="text-xs">{l.ecosystem}</td>
                <td className="text-xs text-slate-400">{l.known_algorithms.join(", ") || "—"}</td>
                <td className="text-xs font-mono text-slate-500 max-w-xs truncate">{l.source_file}</td>
                <td className="text-xs text-slate-500">{(l.confidence * 100).toFixed(0)}%</td>
              </tr>
            ))}
            {libs.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center text-slate-500 py-4">No crypto-capable libraries found for this scan.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
