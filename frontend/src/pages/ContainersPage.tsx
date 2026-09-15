import { useEffect, useState } from "react";
import api from "../services/api";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

interface ContainerFinding {
  id: string;
  algorithm: string;
  file: string;
  usage: string;
  library: string;
  confidence: number;
}

export default function ContainersPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [findings, setFindings] = useState<ContainerFinding[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get("/containers", { params: { scan_id: scanId } }).then((res) => setFindings(res.data));
  }, [scanId]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Containers</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>
      <p className="text-xs text-slate-500">
        Static Dockerfile/container build-context analysis. Does not use the Docker daemon and never pulls, builds, or executes an image.
      </p>

      <div className="card p-0 overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Base Package</th>
              <th>Dockerfile</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td className="font-medium">{f.algorithm}</td>
                <td className="text-xs">{f.library}</td>
                <td className="text-xs font-mono text-slate-500 max-w-xs truncate">{f.file}</td>
                <td className="text-xs text-slate-500">{(f.confidence * 100).toFixed(0)}%</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td colSpan={4} className="text-center text-slate-500 py-4">No container-related findings for this scan.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
