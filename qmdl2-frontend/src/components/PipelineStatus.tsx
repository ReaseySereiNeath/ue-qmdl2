"use client";

import type { ParseStatus } from "@/types/log";

const STEPS: { key: ParseStatus; label: string }[] = [
  { key: "uploading", label: "Uploading QMDL2 file" },
  { key: "scat_decoding", label: "SCAT: QMDL2 → PCAP" },
  { key: "tshark_parsing", label: "tshark: PCAP → JSON" },
  { key: "normalizing", label: "Normalizing to JSON schema" },
];

interface PipelineStatusProps {
  currentStatus: ParseStatus;
}

export function PipelineStatus({ currentStatus }: PipelineStatusProps) {
  const stepKeys = STEPS.map((s) => s.key);
  const currentIdx = stepKeys.indexOf(currentStatus);

  return (
    <div className="mt-8 flex flex-col gap-2">
      {STEPS.map((step, i) => {
        const isDone = i < currentIdx;
        const isCurrent = i === currentIdx;

        return (
          <div
            key={step.key}
            className="flex items-center gap-2.5"
            style={{ opacity: isDone || isCurrent ? 1 : 0.3 }}
          >
            <span
              className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold"
              style={{
                background: isDone
                  ? "rgba(34,197,94,0.15)"
                  : isCurrent
                    ? "rgba(56,189,248,0.15)"
                    : "rgba(148,163,184,0.05)",
                color: isDone
                  ? "#22c55e"
                  : isCurrent
                    ? "#38bdf8"
                    : "#475569",
                border: `1px solid ${
                  isDone
                    ? "rgba(34,197,94,0.3)"
                    : isCurrent
                      ? "rgba(56,189,248,0.3)"
                      : "rgba(148,163,184,0.1)"
                }`,
              }}
            >
              {isDone ? "✓" : i + 1}
            </span>
            <span
              className="font-[var(--font-mono)] text-xs font-semibold"
              style={{
                color: isDone
                  ? "#22c55e"
                  : isCurrent
                    ? "#38bdf8"
                    : "#475569",
              }}
            >
              {step.label}
            </span>
            {isCurrent && (
              <span className="animate-pulse-dot text-[10px] text-sky-400">
                ●
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
