"use client";

import { useMemo } from "react";
import type { LogEntry } from "@/types/log";

interface StatsBarProps {
  logs: LogEntry[];
}

export function StatsBar({ logs }: StatsBarProps) {
  const stats = useMemo(() => {
    const s = {
      total: logs.length,
      info: 0,
      warning: 0,
      error: 0,
      critical: 0,
      protocols: new Set<string>(),
      ues: new Set<string>(),
    };
    logs.forEach((l) => {
      s[l.severity]++;
      s.protocols.add(l.protocol);
      s.ues.add(l.imsi);
    });
    return s;
  }, [logs]);

  const items = [
    { label: "Total", value: stats.total, color: "#e2e8f0" },
    { label: "Errors", value: stats.error + stats.critical, color: "#ef4444" },
    { label: "Warnings", value: stats.warning, color: "#fbbf24" },
    { label: "Protocols", value: stats.protocols.size, color: "#38bdf8" },
    { label: "UEs", value: stats.ues.size, color: "#a78bfa" },
  ];

  return (
    <div className="hidden flex-wrap gap-x-4 gap-y-1 sm:flex">
      {items.map((s) => (
        <div key={s.label} className="flex items-baseline gap-1.5">
          <span
            className="font-[var(--font-mono)] text-base font-extrabold lg:text-lg"
            style={{ color: s.color }}
          >
            {s.value}
          </span>
          <span className="font-[var(--font-mono)] text-[9px] font-semibold uppercase tracking-wide text-slate-600">
            {s.label}
          </span>
        </div>
      ))}
    </div>
  );
}
