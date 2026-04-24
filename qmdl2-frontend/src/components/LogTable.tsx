"use client";

import { useState, useEffect } from "react";
import type { LogEntry } from "@/types/log";
import { SeverityBadge } from "./SeverityBadge";
import { ProtocolBadge } from "./ProtocolBadge";

interface LogTableProps {
  logs: LogEntry[];
  selectedLog: LogEntry | null;
  onSelectLog: (log: LogEntry) => void;
}

const PAGE_SIZE = 50;

function formatTime(iso: string): string {
  const d = new Date(iso);
  return (
    d.toLocaleTimeString("en-GB", { hour12: false }) +
    "." +
    String(d.getMilliseconds()).padStart(3, "0")
  );
}

export function LogTable({ logs, selectedLog, onSelectLog }: LogTableProps) {
  const [page, setPage] = useState(0);
  const totalPages = Math.ceil(logs.length / PAGE_SIZE);
  const pageLogs = logs.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  useEffect(() => {
    setPage(0);
  }, [logs.length]);

  const getRowBg = (log: LogEntry, idx: number): string => {
    if (selectedLog?.id === log.id) return "rgba(56,189,248,0.08)";
    if (log.severity === "critical") return "rgba(239,68,68,0.06)";
    if (log.severity === "error") return "rgba(248,113,113,0.04)";
    return idx % 2 === 0 ? "transparent" : "rgba(148,163,184,0.02)";
  };

  const getLeftBorder = (log: LogEntry): string => {
    if (log.severity === "critical") return "3px solid #ef4444";
    if (log.severity === "error") return "3px solid rgba(248,113,113,0.4)";
    return "3px solid transparent";
  };

  const HEADERS = ["Time", "Severity", "Protocol", "Event", "IMSI", "gNB", "Message"];

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse font-[var(--font-mono)] text-xs">
          <thead>
            <tr style={{ position: "sticky", top: 0, background: "#0c1222", zIndex: 2 }}>
              {HEADERS.map((h) => (
                <th
                  key={h}
                  className={`border-b border-slate-700/20 px-2 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-600 sm:px-2.5 ${
                    h === "IMSI" || h === "gNB" ? "hidden md:table-cell" : ""
                  } ${h === "Event" ? "hidden sm:table-cell" : ""}`}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageLogs.map((log, idx) => (
              <tr
                key={log.id}
                onClick={() => onSelectLog(log)}
                className="cursor-pointer transition-colors duration-150 hover:!bg-slate-700/10"
                style={{
                  background: getRowBg(log, idx),
                  borderLeft: getLeftBorder(log),
                }}
              >
                <td className="whitespace-nowrap px-2 py-1.5 text-slate-400 sm:px-2.5">
                  {formatTime(log.timestamp)}
                </td>
                <td className="px-2 py-1.5 sm:px-2.5">
                  <SeverityBadge severity={log.severity} />
                </td>
                <td className="px-2 py-1.5 sm:px-2.5">
                  <ProtocolBadge protocol={log.protocol} />
                </td>
                <td className="hidden px-2.5 py-1.5 font-medium text-slate-300 sm:table-cell">
                  {log.eventType}
                </td>
                <td className="hidden px-2.5 py-1.5 text-[11px] text-slate-500 md:table-cell">
                  {log.imsi.slice(-6)}
                </td>
                <td className="hidden px-2.5 py-1.5 text-[11px] text-slate-500 md:table-cell">
                  {log.gNBId.split("-").slice(0, 2).join("-")}
                </td>
                <td
                  className="max-w-[150px] truncate px-2 py-1.5 sm:max-w-[300px] sm:px-2.5"
                  style={{
                    color:
                      log.severity === "error" || log.severity === "critical"
                        ? "#f87171"
                        : "#94a3b8",
                  }}
                >
                  {log.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between border-t border-slate-700/15 px-3 py-2 font-[var(--font-mono)] text-[11px] text-slate-500">
        <span>{logs.length} entries</span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="rounded border border-slate-700/25 bg-slate-700/15 px-2 py-0.5 text-slate-400 disabled:opacity-30"
          >
            ←
          </button>
          <span className="px-2 text-slate-200">
            {page + 1}/{totalPages || 1}
          </span>
          <button
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="rounded border border-slate-700/25 bg-slate-700/15 px-2 py-0.5 text-slate-400 disabled:opacity-30"
          >
            →
          </button>
        </div>
      </div>
    </div>
  );
}
