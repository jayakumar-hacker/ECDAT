import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { logout } from "../services/api";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/scan", label: "Scan" },
  { to: "/scan-history", label: "Scan History" },
  { to: "/inventory", label: "Inventory" },
  { to: "/cbom", label: "CBOM Explorer" },
  { to: "/dependency-graph", label: "Dependency Graph" },
  { to: "/quantum-risk", label: "Quantum Risk" },
  { to: "/mosca", label: "Mosca Analysis" },
  { to: "/recommendations", label: "PQC Recommendations" },
  { to: "/migration-simulator", label: "Migration Simulator" },
  { to: "/certificates", label: "Certificates" },
  { to: "/libraries", label: "Libraries" },
  { to: "/containers", label: "Containers" },
  { to: "/reports", label: "Reports" },
  { to: "/ai-assistant", label: "AI Assistant" },
  { to: "/settings", label: "Settings" },
  { to: "/posture-drift", label: "Posture Drift" },
  { to: "/hndl-exposure", label: "HNDL Exposure" },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const role = localStorage.getItem("ecdat_role") || "user";

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="flex h-screen bg-slate-950">
      <aside className="w-60 bg-panel2 border-r border-slate-800 flex flex-col shrink-0">
        <div className="px-4 py-4 border-b border-slate-800">
          <div className="text-sky-400 font-bold text-lg tracking-tight">CRYPTORA</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wide">Crypto Discovery &amp; Analysis</div>
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block px-4 py-2 text-sm ${
                  isActive ? "bg-sky-950 text-sky-400 border-r-2 border-sky-500" : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-slate-800 text-xs text-slate-500">
          Role: <span className="text-slate-300">{role}</span>
          <button onClick={handleLogout} className="block mt-2 text-red-400 hover:text-red-300">
            Log out
          </button>
        </div>
      </aside>
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-12 bg-panel2 border-b border-slate-800 flex items-center px-4 justify-between shrink-0">
          <div className="text-xs text-slate-500">Defensive security tool — read-only scanning, offline-first</div>
          <div className="flex items-center gap-2 text-xs text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> Backend Connected
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
