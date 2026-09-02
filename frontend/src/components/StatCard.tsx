export default function StatCard({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  const toneClass = tone ? `text-${tone}` : "text-slate-100";
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${toneClass}`}>{value}</div>
    </div>
  );
}
