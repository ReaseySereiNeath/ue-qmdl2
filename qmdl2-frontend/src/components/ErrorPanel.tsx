"use client";

import { useMemo } from "react";
import type { LogEntry, AnomalyGroup } from "@/types/log";

interface ErrorPanelProps {
  logs: LogEntry[];
}

export function ErrorPanel({ logs }: ErrorPanelProps) {
  const anomalies = useMemo((): AnomalyGroup[] => {
    const errors = logs.filter(
      (l) => l.severity === "error" || l.severity === "critical"
    );
    const groups: Record<string, AnomalyGroup> = {};

    errors.forEach((e) => {
      if (!groups[e.eventType]) {
        groups[e.eventType] = {
          eventType: e.eventType,
          count: 0,
          logs: [],
          imsis: new Set(),
        };
      }
      groups[e.eventType].count++;
      groups[e.eventType].logs.push(e);
      groups[e.eventType].imsis.add(e.imsi);
    });

    return Object.values(groups).sort((a, b) => b.count - a.count);
  }, [logs]);

  const totalErrors = anomalies.reduce((s, a) => s + a.count, 0);

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex items-baseline gap-2.5">
        <div className="font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
          Anomalies Detected
        </div>
        <span
          className="font-[var(--font-mono)] text-lg font-extrabold"
          style={{ color: totalErrors > 0 ? "#ef4444" : "#22c55e" }}
        >
          {totalErrors}
        </span>
      </div>

      {anomalies.length === 0 ? (
        <div className="py-5 text-center text-[13px] text-emerald-500">
          No anomalies detected
        </div>
      ) : (
        <div className="flex max-h-[50vh] flex-col gap-1.5 overflow-y-auto sm:max-h-[300px]">
          {anomalies.map((a, i) => (
            <div
              key={i}
              className="rounded-md border border-red-500/12 bg-red-500/5 px-3 py-2.5"
            >
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="font-[var(--font-mono)] text-xs font-semibold text-red-400">
                  {a.eventType}
                </span>
                <span className="shrink-0 rounded bg-red-500/15 px-1.5 py-0.5 font-[var(--font-mono)] text-[11px] font-bold text-red-500">
                  {a.count}x
                </span>
              </div>
              <div className="text-[10px] leading-relaxed text-slate-400">
                Affected UEs:{" "}
                {[...a.imsis].map((i) => i.slice(-6)).join(", ")} — Last:{" "}
                {a.logs[a.logs.length - 1].message}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
