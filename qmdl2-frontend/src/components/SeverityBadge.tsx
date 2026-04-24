import type { Severity } from "@/types/log";

const COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  info: {
    bg: "rgba(56,189,248,0.12)",
    text: "#38bdf8",
    border: "rgba(56,189,248,0.25)",
  },
  warning: {
    bg: "rgba(251,191,36,0.12)",
    text: "#fbbf24",
    border: "rgba(251,191,36,0.25)",
  },
  error: {
    bg: "rgba(248,113,113,0.12)",
    text: "#f87171",
    border: "rgba(248,113,113,0.25)",
  },
  critical: {
    bg: "rgba(239,68,68,0.2)",
    text: "#ef4444",
    border: "rgba(239,68,68,0.4)",
  },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const c = COLORS[severity] || COLORS.info;
  return (
    <span
      className="inline-flex items-center gap-1.5 font-[var(--font-mono)] text-[11px] font-semibold uppercase tracking-wide"
      style={{
        padding: "2px 8px",
        borderRadius: 4,
        background: c.bg,
        color: c.text,
        border: `1px solid ${c.border}`,
      }}
    >
      {severity === "critical" && (
        <span
          className="animate-pulse-dot inline-block rounded-full"
          style={{ width: 6, height: 6, background: c.text }}
        />
      )}
      {severity}
    </span>
  );
}
