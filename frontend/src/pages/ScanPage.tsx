import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import type { Scan } from "../types";

const SCANNER_OPTIONS = [
  { key: "source", label: "Source Code" },
  { key: "dependency", label: "Dependencies" },
  { key: "certificate", label: "Certificates" },
  { key: "binary", label: "Binaries" },
  { key: "container", label: "Containers" },
];

export default function ScanPage() {
  const [target, setTarget] = useState("demo");
  const [targetType, setTargetType] = useState("demo");
  const [scanners, setScanners] = useState<string[]>(SCANNER_OPTIONS.map((s) => s.key));
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const navigate = useNavigate();

  function toggleScanner(key: string) {
    setScanners((prev) => (prev.includes(key) ? prev.filter((s) => s !== key) : [...prev, key]));
  }

  async function startScan() {
    setError(null);
    setScan(null);
    try {
      const res = await api.post("/scans", { target, target_type: targetType, scanners });
      setScan(res.data);
      poll(res.data.id);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Failed to start scan");
    }
  }

  function poll(scanId: string) {
    setPolling(true);
    const interval = setInterval(async () => {
      const res = await api.get(`/scans/${scanId}`);
      setScan(res.data);
      if (res.data.status === "completed" || res.data.status === "failed") {
        clearInterval(interval);
        setPolling(false);
      }
    }, 1200);
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <h1 className="text-xl font-semibold text-slate-100">Scan</h1>

      <div className="card space-y-4">
        <div>
          <label className="text-xs text-slate-400 block mb-1">Target</label>
          <div className="flex gap-2">
            <select
              className="input w-40"
              value={targetType}
              onChange={(e) => {
                setTargetType(e.target.value);
                if (e.target.value === "demo") setTarget("demo");
              }}
            >
              <option value="demo">Demo Repository</option>
              <option value="directory">Directory</option>
              <option value="file">Single File</option>
            </select>
            {targetType !== "demo" && (
              <input
                className="input"
                placeholder="/absolute/path/to/target (server-side path)"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            )}
          </div>
          {targetType === "demo" && (
            <p className="text-xs text-slate-500 mt-1">
              Scans the bundled fictional Acme Corp demo repository (6 systems, intentionally includes RSA-1024/2048/4096, ECDSA, ECDH, AES-128/256, SHA-1, MD5, DES, TLS config, and certificates).
            </p>
          )}
        </div>

        <div>
          <label className="text-xs text-slate-400 block mb-2">Scanners</label>
          <div className="grid grid-cols-2 gap-2">
            {SCANNER_OPTIONS.map((opt) => (
              <label key={opt.key} className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={scanners.includes(opt.key)} onChange={() => toggleScanner(opt.key)} />
                {opt.label}
              </label>
            ))}
          </div>
        </div>

        {error && <div className="text-red-400 text-sm">{error}</div>}

        <button className="btn-primary" onClick={startScan} disabled={polling}>
          {polling ? "Scanning..." : "Start Scan"}
        </button>
      </div>

      {scan && (
        <div className="card space-y-3">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-semibold text-slate-300">Scan {scan.id.slice(0, 8)}</h2>
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded ${
                scan.status === "completed"
                  ? "bg-emerald-950 text-emerald-400"
                  : scan.status === "failed"
                  ? "bg-red-950 text-red-400"
                  : "bg-sky-950 text-sky-400"
              }`}
            >
              {scan.status.toUpperCase()}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-slate-500">Files scanned: </span>
              <span className="text-slate-200">{scan.files_scanned}</span>
            </div>
            <div>
              <span className="text-slate-500">Artefacts found: </span>
              <span className="text-slate-200">{scan.artefacts_found}</span>
            </div>
          </div>
          {scan.errors.length > 0 && (
            <div className="text-xs text-amber-400">
              {scan.errors.length} scanner warning(s)/error(s) recorded (non-fatal).
            </div>
          )}
          {scan.status === "completed" && (
            <button className="btn-secondary" onClick={() => navigate(`/inventory?scan_id=${scan.id}`)}>
              View Results
            </button>
          )}
        </div>
      )}
    </div>
  );
}
