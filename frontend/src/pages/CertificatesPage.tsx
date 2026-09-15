import { useEffect, useState } from "react";
import api from "../services/api";
import type { Certificate } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

export default function CertificatesPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [certs, setCerts] = useState<Certificate[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get("/certificates", { params: { scan_id: scanId } }).then((res) => setCerts(res.data));
  }, [scanId]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Certificates</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      <div className="card p-0 overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Subject</th>
              <th>Algorithm</th>
              <th>Key Size</th>
              <th>Signature</th>
              <th>Expires</th>
              <th>Days Left</th>
              <th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.id}>
                <td className="text-xs">{c.parse_error ? <span className="text-red-400">{c.file}</span> : c.subject}</td>
                <td>{c.public_key_algorithm}</td>
                <td>{c.key_size || "—"}</td>
                <td className="text-xs">{c.signature_algorithm}</td>
                <td className="text-xs text-slate-500">{c.valid_until ? new Date(c.valid_until).toLocaleDateString() : "—"}</td>
                <td className={c.expired ? "text-red-400" : (c.days_remaining || 999) < 30 ? "text-amber-400" : "text-slate-300"}>
                  {c.expired ? "Expired" : c.days_remaining ?? "—"}
                </td>
                <td className="space-x-1">
                  {c.weak_key && <span className="badge-HIGH text-xs px-1.5 py-0.5 rounded">Weak Key</span>}
                  {c.weak_signature && <span className="badge-HIGH text-xs px-1.5 py-0.5 rounded">Weak Sig</span>}
                  {c.parse_error && <span className="badge-MEDIUM text-xs px-1.5 py-0.5 rounded">Parse Error</span>}
                </td>
              </tr>
            ))}
            {certs.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center text-slate-500 py-4">No certificates found for this scan.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
