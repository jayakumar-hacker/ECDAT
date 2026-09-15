import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../services/api";
import type { Scan } from "../types";

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get("/scans").then((res) => setScans(res.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-slate-400">Loading...</div>;

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-100">Scan History</h1>
      {scans.length === 0 ? (
        <div className="card text-slate-400 text-sm">No scans yet. Run one from the Scan page.</div>
      ) : (
        <div className="card p-0 overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Files</th>
                <th>Artefacts</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td className="font-mono text-xs">{s.target}</td>
                  <td>
                    <span
                      className={
                        s.status === "completed"
                          ? "text-emerald-400"
                          : s.status === "failed"
                          ? "text-red-400"
                          : "text-sky-400"
                      }
                    >
                      {s.status}
                    </span>
                  </td>
                  <td>{s.files_scanned}</td>
                  <td>{s.artefacts_found}</td>
                  <td className="text-xs text-slate-500">{new Date(s.created_at).toLocaleString()}</td>
                  <td>
                    <Link to={`/inventory?scan_id=${s.id}`} className="text-sky-400 hover:underline text-xs">
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
