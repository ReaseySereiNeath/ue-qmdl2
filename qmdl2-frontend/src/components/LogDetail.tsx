"use client";

import type { LogEntry } from "@/types/log";

interface LogDetailProps {
  log: LogEntry;
  onClose: () => void;
}

export function LogDetail({ log, onClose }: LogDetailProps) {
  const fields: [string, string | number][] = [
    ["Timestamp", log.timestamp],
    ["Protocol", log.protocol],
    ["Event Type", log.eventType],
    ["Severity", log.severity],
    ["IMSI", log.imsi || "—"],
    ["SUPI", log.supi || "—"],
    ["gNB ID", log.gNBId || "—"],
    ["PCI", log.pci || "—"],
    ["ARFCN", log.metadata?.arfcn ?? "—"],
    ["RSRP", log.metadata?.rsrp ? `${log.metadata.rsrp} dBm` : "—"],
    ["SINR", log.metadata?.sinr ? `${log.metadata.sinr} dB` : "—"],
    ["Message", log.message],
  ];

  const detailEntries = Object.entries(log.details || {});

  return (
    <>
      {/* Mobile backdrop */}
      <div
        className="fixed inset-0 z-[99] bg-black/50 sm:hidden"
        onClick={onClose}
      />
      <div
        className="animate-slide-in fixed bottom-0 right-0 top-0 z-[100] flex w-full flex-col border-l border-slate-700/20 bg-[#0c1222] sm:w-[380px]"
        style={{ boxShadow: "-20px 0 60px rgba(0,0,0,0.4)" }}
      >
        <div className="flex items-center justify-between border-b border-slate-700/15 px-4 py-3.5">
          <span className="font-[var(--font-mono)] text-xs font-bold text-slate-200">
            Log Detail
          </span>
          <span
            onClick={onClose}
            className="cursor-pointer text-lg leading-none text-slate-500 hover:text-slate-300"
          >
            ×
          </span>
        </div>
        <div className="flex-1 overflow-y-auto p-4">
          {fields.map(([label, value]) => (
            <div key={label} className="mb-3">
              <div className="mb-0.5 font-[var(--font-mono)] text-[9px] font-bold uppercase tracking-widest text-slate-600">
                {label}
              </div>
              <div className="break-all font-[var(--font-mono)] text-xs text-slate-300">
                {String(value)}
              </div>
            </div>
          ))}

          {detailEntries.length > 0 && (
            <div className="mt-2">
              <div className="mb-1 font-[var(--font-mono)] text-[9px] font-bold uppercase tracking-widest text-slate-600">
                Details
              </div>
              <div className="overflow-hidden rounded bg-black/30 p-2.5 font-[var(--font-mono)] text-[11px] leading-relaxed text-sky-400">
                {detailEntries.map(([key, val]) => (
                  <div key={key} className="break-all">
                    <span className="text-slate-500">{key}:</span> {val}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
