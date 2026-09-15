import type { Scan } from "../types";

export default function ScanSelector({
  scans,
  scanId,
  onChange,
}: {
  scans: Scan[];
  scanId: string;
  onChange: (id: string) => void;
}) {
  if (scans.length === 0) {
    return <div className="text-xs text-slate-500">No scans available yet.</div>;
  }
  return (
    <select className="input w-auto" value={scanId} onChange={(e) => onChange(e.target.value)}>
      {scans.map((s) => (
        <option key={s.id} value={s.id}>
          {s.target.split("/").pop()} — {new Date(s.created_at).toLocaleString()} ({s.artefacts_found} artefacts)
        </option>
      ))}
    </select>
  );
}
