import { useState } from "react";
import api from "../services/api";
import ScanSelector from "../components/ScanSelector";
import { useScanSelector } from "../hooks/useScanSelector";

interface ChatEntry {
  question: string;
  answer: string;
  mode: string;
  note?: string;
}

const EXAMPLE_QUESTIONS = [
  "Which systems are most vulnerable to quantum attacks?",
  "Which RSA assets should migrate first?",
  "How many SHA-1 assets exist?",
  "What PQC replacement is recommended?",
  "Explain the Mosca analysis",
];

export default function AiAssistantPage() {
  const { scanId, scans, setScanId } = useScanSelector();
  const [question, setQuestion] = useState("");
  const [history, setHistory] = useState<ChatEntry[]>([]);
  const [loading, setLoading] = useState(false);

  async function ask(q: string) {
    if (!q.trim()) return;
    setLoading(true);
    try {
      const res = await api.post("/ai/chat", { question: q, scan_id: scanId || null });
      setHistory((prev) => [...prev, { question: q, answer: res.data.answer, mode: res.data.mode, note: res.data.note }]);
      setQuestion("");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-slate-100">AI Assistant</h1>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>
      <p className="text-xs text-slate-500">
        Runs in deterministic mode by default (no LLM required, works fully offline) — it retrieves structured ECDAT
        data before answering and never invents scan findings. An LLM backend (Ollama or OpenAI-compatible) can
        optionally be configured server-side.
      </p>

      <div className="flex flex-wrap gap-2">
        {EXAMPLE_QUESTIONS.map((q) => (
          <button key={q} className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded" onClick={() => ask(q)}>
            {q}
          </button>
        ))}
      </div>

      <div className="card space-y-4 min-h-[300px]">
        {history.length === 0 && <div className="text-slate-500 text-sm">Ask a question about this scan's findings.</div>}
        {history.map((h, i) => (
          <div key={i} className="space-y-1">
            <div className="text-sky-400 text-sm font-medium">{h.question}</div>
            <div className="text-slate-300 text-sm whitespace-pre-wrap bg-slate-900 rounded p-3">{h.answer}</div>
            {h.note && <div className="text-xs text-slate-600 italic">{h.note}</div>}
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          className="input"
          placeholder="Ask about this scan..."
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && ask(question)}
        />
        <button className="btn-primary" onClick={() => ask(question)} disabled={loading}>
          {loading ? "..." : "Ask"}
        </button>
      </div>
    </div>
  );
}
