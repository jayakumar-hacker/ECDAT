import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import api from "../services/api";
import type { Asset } from "../types";
import SeverityBadge from "../components/SeverityBadge";

export default function AssetDetailsPage() {
  const { id } = useParams();
  const [asset, setAsset] = useState<Asset | null>(null);

  useEffect(() => {
    if (id) api.get(`/assets/${id}`).then((res) => setAsset(res.data));
  }, [id]);

  if (!asset) return <div className="text-slate-400">Loading...</div>;

  return (
    <div className="space-y-6 max-w-3xl">
      <Link to="/inventory" className="text-sky-400 text-sm hover:underline">
        ← Back to Inventory
      </Link>
      <h1 className="text-xl font-semibold text-slate-100">{asset.name}</h1>

      <div className="card grid grid-cols-2 gap-4 text-sm">
        <div>
          <div className="text-slate-500 text-xs">Algorithm</div>
          <div className="text-slate-200">{asset.algorithm_name}</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Key Size</div>
          <div className="text-slate-200">{asset.key_size || "Not applicable / not determined"}</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Purpose</div>
          <div className="text-slate-200">{asset.purpose || "—"}</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Location</div>
          <div className="text-slate-200 font-mono text-xs">{asset.location}</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Business Asset</div>
          <div className="text-slate-200">{asset.business_asset || "Not linked"}</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Detection Confidence</div>
          <div className="text-slate-200">{(asset.confidence * 100).toFixed(0)}%</div>
        </div>
      </div>

      {asset.risk && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-300">Quantum Risk Assessment</h2>
            <SeverityBadge severity={asset.risk.severity} />
          </div>
          <div className="text-3xl font-bold text-slate-100">{asset.risk.score}/100</div>
          <div className="space-y-1">
            {asset.risk.factors.map((f, i) => (
              <div key={i} className="flex justify-between text-xs border-b border-slate-900 py-1">
                <span className="text-slate-400">{f.name.replace(/_/g, " ")}</span>
                <span className="text-slate-300">+{f.impact}</span>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-500">
            This is the ECDAT scoring model, not an official NIST/CVSS score. See docs/risk-model.md for methodology.
          </p>
        </div>
      )}

      {asset.mosca && (
        <div className="card space-y-2">
          <h2 className="text-sm font-semibold text-slate-300">Mosca Analysis</h2>
          <div className="grid grid-cols-3 gap-3 text-sm">
            <div>
              <div className="text-slate-500 text-xs">X (data lifetime)</div>
              <div className="text-slate-200">{asset.mosca.x_data_lifetime_years}y</div>
            </div>
            <div>
              <div className="text-slate-500 text-xs">Y (migration time)</div>
              <div className="text-slate-200">{asset.mosca.y_migration_time_years}y</div>
            </div>
            <div>
              <div className="text-slate-500 text-xs">Z (threat horizon)</div>
              <div className="text-slate-200">{asset.mosca.z_threat_horizon_years}y</div>
            </div>
          </div>
          <div className="text-sm">
            X+Y = <span className="font-semibold">{asset.mosca.x_plus_y}y</span> vs Z ={" "}
            {asset.mosca.z_threat_horizon_years}y →{" "}
            <span
              className={
                asset.mosca.result === "URGENT MIGRATION"
                  ? "text-red-400 font-semibold"
                  : asset.mosca.result === "PLAN MIGRATION"
                  ? "text-orange-400 font-semibold"
                  : "text-slate-300"
              }
            >
              {asset.mosca.result}
            </span>
          </div>
        </div>
      )}

      {asset.recommendation && (
        <div className="card space-y-2">
          <h2 className="text-sm font-semibold text-slate-300">PQC Recommendation</h2>
          <div className="text-sm">
            <span className="text-slate-400">{asset.recommendation.current_algorithm}</span>
            {" → "}
            <span className="text-emerald-400 font-medium">{asset.recommendation.recommended_algorithm}</span>
          </div>
          {asset.recommendation.hybrid_option && (
            <div className="text-xs text-slate-500">Hybrid option: {asset.recommendation.hybrid_option}</div>
          )}
          <p className="text-xs text-slate-400">{asset.recommendation.reason}</p>
          <div className="text-xs text-slate-500">Migration complexity: {asset.recommendation.migration_complexity}</div>
        </div>
      )}
    </div>
  );
}
