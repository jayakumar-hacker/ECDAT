export default function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`badge-${severity} text-xs font-semibold px-2 py-0.5 rounded`}>
      {severity}
    </span>
  );
}
