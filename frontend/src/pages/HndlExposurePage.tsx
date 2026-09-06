import { useEffect, useState } from "react";
import api from "../services/api";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";
import type { Asset } from "../types";

export default function HndlExposurePage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get("/hndl", { params: { scan_id: scanId } })
      .then((res) => setAssets(res.data.assets || []));
  }, [scanId]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-100">HNDL Exposure</h1>
      <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      <div className="card p-0 overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Location</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id}>
                <td className="font-medium text-slate-200">{a.algorithm_name}</td>
                <td className="font-mono text-xs text-slate-500 max-w-xs truncate" title={a.location}>
                  {a.location}
                </td>
                <td className="text-xs text-slate-400">{a.hndl_reason || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
