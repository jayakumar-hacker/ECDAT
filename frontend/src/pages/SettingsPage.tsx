export default function SettingsPage() {
  const role = localStorage.getItem("ecdat_role") || "user";
  return (
    <div className="space-y-4 max-w-xl">
      <h1 className="text-xl font-semibold text-slate-100">Settings</h1>
      <div className="card space-y-3 text-sm">
        <div>
          <div className="text-slate-500 text-xs">Signed in as</div>
          <div className="text-slate-200">{role}</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Risk scoring thresholds</div>
          <div className="text-slate-300 text-xs">
            LOW: 0–24, MEDIUM: 25–49, HIGH: 50–74, CRITICAL: 75–100 (configurable server-side via app/core/config.py)
          </div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Default Mosca threat horizon</div>
          <div className="text-slate-300 text-xs">10 years (configurable per-asset in the Mosca Analysis page)</div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">AI Assistant</div>
          <div className="text-slate-300 text-xs">
            Disabled by default (deterministic fallback only). Enable server-side via .env (AI_ENABLED, AI_PROVIDER).
          </div>
        </div>
        <div>
          <div className="text-slate-500 text-xs">Data handling</div>
          <div className="text-slate-300 text-xs">
            Scanning is read-only. Private key files are detected and refused, never parsed. Source code is never
            sent to an external AI provider unless explicitly configured.
          </div>
        </div>
      </div>
    </div>
  );
}
