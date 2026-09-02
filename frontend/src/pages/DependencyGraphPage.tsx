import { useEffect, useState } from "react";
import api from "../services/api";
import type { Asset, Library } from "../types";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

interface GraphNode {
  id: string;
  label: string;
  type: "application" | "library" | "algorithm";
  x: number;
  y: number;
}
interface GraphEdge {
  from: string;
  to: string;
}

export default function DependencyGraphPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [libraries, setLibraries] = useState<Library[]>([]);

  useEffect(() => {
    if (!scanId) return;
    api.get("/assets", { params: { scan_id: scanId } }).then((res) => setAssets(res.data));
    api.get("/libraries", { params: { scan_id: scanId } }).then((res) => setLibraries(res.data));
  }, [scanId]);

  // Build a simple layered graph: business assets -> libraries -> algorithms
  const appNames = Array.from(new Set(assets.map((a) => a.business_asset).filter(Boolean))) as string[];
  const algoNames = Array.from(new Set(assets.map((a) => a.algorithm_name).filter(Boolean))).slice(0, 12) as string[];
  const libNames = libraries.slice(0, 10).map((l) => l.name);

  const nodes: GraphNode[] = [
    ...appNames.map((n, i) => ({ id: `app-${n}`, label: n, type: "application" as const, x: 80, y: 60 + i * 60 })),
    ...libNames.map((n, i) => ({ id: `lib-${n}`, label: n, type: "library" as const, x: 380, y: 40 + i * 45 })),
    ...algoNames.map((n, i) => ({ id: `algo-${n}`, label: n, type: "algorithm" as const, x: 680, y: 30 + i * 40 })),
  ];

  const edges: GraphEdge[] = [];
  assets.forEach((a) => {
    if (a.business_asset && a.component) {
      edges.push({ from: `app-${a.business_asset}`, to: `lib-${a.component}` });
    }
    if (a.component && a.algorithm_name && libNames.includes(a.component)) {
      edges.push({ from: `lib-${a.component}`, to: `algo-${a.algorithm_name}` });
    }
  });

  const findNode = (id: string) => nodes.find((n) => n.id === id);
  const colorFor = (type: string) => (type === "application" ? "#38bdf8" : type === "library" ? "#a78bfa" : "#f97316");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Dependency Graph</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>
      <p className="text-xs text-slate-500">
        Application → Library → Algorithm relationships derived from normalized scan data.
      </p>
      <div className="card overflow-x-auto">
        {nodes.length === 0 ? (
          <div className="text-slate-400 text-sm">No graph data for this scan yet.</div>
        ) : (
          <svg width="900" height={Math.max(400, nodes.length * 40)} className="min-w-[900px]">
            {edges.map((e, i) => {
              const from = findNode(e.from);
              const to = findNode(e.to);
              if (!from || !to) return null;
              return (
                <line key={i} x1={from.x + 60} y1={from.y} x2={to.x - 10} y2={to.y} stroke="#334155" strokeWidth={1} />
              );
            })}
            {nodes.map((n) => (
              <g key={n.id}>
                <rect
                  x={n.x - 60}
                  y={n.y - 14}
                  width={n.type === "algorithm" ? 130 : 140}
                  height={28}
                  rx={6}
                  fill="#0f172a"
                  stroke={colorFor(n.type)}
                  strokeWidth={1.5}
                />
                <text x={n.x + (n.type === "algorithm" ? 5 : 10)} y={n.y + 4} fontSize={11} fill="#e2e8f0" textAnchor="middle">
                  {n.label.length > 18 ? n.label.slice(0, 16) + "…" : n.label}
                </text>
              </g>
            ))}
          </svg>
        )}
      </div>
      <div className="flex gap-4 text-xs text-slate-400">
        <span><span className="inline-block w-3 h-3 rounded bg-sky-400 mr-1" />Application</span>
        <span><span className="inline-block w-3 h-3 rounded bg-violet-400 mr-1" />Library</span>
        <span><span className="inline-block w-3 h-3 rounded bg-orange-500 mr-1" />Algorithm</span>
      </div>
    </div>
  );
}
