import { useState } from "react";
import api from "../services/api";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

export default function ReportsPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [generating, setGenerating] = useState(false);
  const [lastReport, setLastReport] = useState<{ filename: string; download_url: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function generate(format: string) {
    if (!scanId) return;
    setGenerating(true);
    setError(null);
    try {
      const res = await api.post("/reports", { scan_id: scanId, format });
      setLastReport(res.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Report generation failed");
    } finally {
      setGenerating(false);
    }
  }

  async function download() {
    if (!lastReport) return;
    const token = localStorage.getItem("ecdat_token");
    const res = await fetch(`/api${lastReport.download_url}`, { headers: { Authorization: `Bearer ${token}` } });
    const blob = await res.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = lastReport.filename;
    link.click();
  }

  return (
    <div className="space-y-4 max-w-xl">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Reports</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      <div className="card space-y-4">
        <p className="text-sm text-slate-400">
          Generates a report containing: Executive Summary, Scan Information, Cryptographic Inventory, Quantum Risk,
          Critical Findings, PQC Recommendations, Migration Priorities, Certificates, Libraries, and Limitations.
        </p>
        <div className="flex gap-2">
          <button className="btn-primary" disabled={!scanId || generating} onClick={() => generate("json")}>
            Generate JSON
          </button>
          <button className="btn-primary" disabled={!scanId || generating} onClick={() => generate("csv")}>
            Generate CSV
          </button>
          <button className="btn-primary" disabled={!scanId || generating} onClick={() => generate("pdf")}>
            Generate PDF
          </button>
        </div>
        {error && <div className="text-red-400 text-sm">{error}</div>}
        {lastReport && (
          <div className="border-t border-slate-800 pt-3 flex items-center justify-between">
            <span className="text-sm text-slate-300">{lastReport.filename}</span>
            <button className="btn-secondary" onClick={download}>
              Download
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
