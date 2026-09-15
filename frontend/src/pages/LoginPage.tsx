import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../services/api";

export default function LoginPage() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      navigate("/");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="card w-full max-w-sm">
        <div className="text-center mb-6">
          <div className="text-sky-400 font-bold text-2xl">ECDAT</div>
          <div className="text-xs text-slate-500 uppercase tracking-wide mt-1">
            Enterprise Cryptographic Discovery &amp; Analysis Tool
          </div>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Username</label>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Password</label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="EcdatDemo123!"
            />
          </div>
          {error && <div className="text-red-400 text-sm">{error}</div>}
          <button type="submit" disabled={loading} className="btn-primary w-full">
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
        <div className="mt-4 text-xs text-slate-500 text-center">
          Demo credentials: <span className="text-slate-300">admin / EcdatDemo123!</span>
        </div>
      </div>
    </div>
  );
}
