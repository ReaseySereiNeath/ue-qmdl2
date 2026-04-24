"use client";

import { useMemo } from "react";
import type { LogEntry, FilterState, Severity } from "@/types/log";

const SEVERITIES: Severity[] = ["info", "warning", "error", "critical"];

interface FilterPanelProps {
  filters: FilterState;
  logs: LogEntry[];
  onFilterChange: (filter: Partial<FilterState>) => void;
}

export function FilterPanel({ filters, logs, onFilterChange }: FilterPanelProps) {
  const uniqueProtocols = useMemo(
    () => [...new Set(logs.map((l) => l.protocol))].sort(),
    [logs]
  );
  const uniqueIMSIs = useMemo(
    () => [...new Set(logs.map((l) => l.imsi))].sort(),
    [logs]
  );

  const toggleArrayFilter = (key: "protocols" | "severities", value: string) => {
    const current = filters[key] as string[];
    const updated = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    onFilterChange({ [key]: updated });
  };

  return (
    <div className="flex flex-col gap-3.5">
      {/* Search */}
      <div className="relative">
        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-sm text-slate-600">
          ⌕
        </span>
        <input
          type="text"
          placeholder="Search logs..."
          value={filters.search}
          onChange={(e) => onFilterChange({ search: e.target.value })}
          className="w-full rounded-md border border-slate-700/30 bg-slate-900/60 py-2 pl-8 pr-3 font-[var(--font-mono)] text-[13px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-sky-500/30"
        />
      </div>

      {/* Protocol Filters */}
      <div>
        <div className="mb-1.5 font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
          Protocol
        </div>
        <div className="flex flex-wrap gap-1">
          {uniqueProtocols.map((p) => (
            <FilterChip
              key={p}
              label={p}
              active={filters.protocols.includes(p)}
              onClick={() => toggleArrayFilter("protocols", p)}
            />
          ))}
        </div>
      </div>

      {/* Severity Filters */}
      <div>
        <div className="mb-1.5 font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
          Severity
        </div>
        <div className="flex flex-wrap gap-1">
          {SEVERITIES.map((s) => (
            <FilterChip
              key={s}
              label={s}
              active={filters.severities.includes(s)}
              onClick={() => toggleArrayFilter("severities", s)}
            />
          ))}
        </div>
      </div>

      {/* IMSI Filter */}
      <div>
        <div className="mb-1.5 font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
          IMSI
        </div>
        <select
          value={filters.imsi}
          onChange={(e) => onFilterChange({ imsi: e.target.value })}
          className="w-full rounded border border-slate-700/30 bg-slate-900/60 px-2 py-1.5 font-[var(--font-mono)] text-xs text-slate-200"
        >
          <option value="">All UEs</option>
          {uniqueIMSIs.map((i) => (
            <option key={i} value={i}>
              {i}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

function FilterChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <span
      onClick={onClick}
      className="cursor-pointer select-none font-[var(--font-mono)] text-[11px] font-medium transition-all duration-200"
      style={{
        padding: "4px 10px",
        borderRadius: 4,
        border: `1px solid ${active ? "rgba(56,189,248,0.4)" : "rgba(148,163,184,0.15)"}`,
        background: active ? "rgba(56,189,248,0.1)" : "transparent",
        color: active ? "#38bdf8" : "#94a3b8",
      }}
    >
      {label}
    </span>
  );
}
