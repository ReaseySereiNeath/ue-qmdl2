"use client";

import { useState, useCallback, useRef } from "react";
import type { ParseStatus } from "@/types/log";

interface FileUploadProps {
  onFileParsed: (file: File) => void;
  isLoading: boolean;
  progress?: number;
  parseStatus?: ParseStatus;
}

const STATUS_LABELS: Partial<Record<ParseStatus, string>> = {
  uploading: "Uploading file to backend...",
  scat_decoding: "SCAT decoding QMDL2 → PCAP...",
  tshark_parsing: "tshark parsing PCAP → JSON...",
  normalizing: "Normalizing log entries...",
};

export function FileUpload({ onFileParsed, isLoading, progress = 0, parseStatus }: FileUploadProps) {
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    (file: File | undefined) => {
      if (!file) return;
      onFileParsed(file);
    },
    [onFileParsed]
  );

  const statusLabel = parseStatus ? STATUS_LABELS[parseStatus] : undefined;
  const pct = Math.round(progress * 100);

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!isLoading) setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        if (!isLoading) handleFile(e.dataTransfer.files[0]);
      }}
      onClick={() => !isLoading && fileRef.current?.click()}
      className={`transition-all duration-300 ${isLoading ? "cursor-default" : "cursor-pointer"}`}
      style={{
        border: `2px dashed ${dragOver ? "#38bdf8" : isLoading ? "rgba(56,189,248,0.3)" : "rgba(148,163,184,0.2)"}`,
        borderRadius: 12,
        padding: "40px 20px",
        textAlign: "center",
        background: dragOver
          ? "rgba(56,189,248,0.04)"
          : isLoading
            ? "rgba(56,189,248,0.02)"
            : "rgba(15,23,42,0.5)",
        backdropFilter: "blur(10px)",
      }}
    >
      <input
        ref={fileRef}
        type="file"
        accept=".qmdl2,.qmdl,.dlf,.qdb"
        hidden
        onChange={(e) => handleFile(e.target.files?.[0])}
      />

      {isLoading ? (
        <>
          {/* Spinner */}
          <div className="mx-auto mb-4 h-10 w-10">
            <svg className="animate-spin" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="rgba(56,189,248,0.2)" strokeWidth="3" />
              <path
                d="M12 2a10 10 0 0 1 10 10"
                stroke="#38bdf8"
                strokeWidth="3"
                strokeLinecap="round"
              />
            </svg>
          </div>

          <div className="mb-1 text-[15px] font-semibold text-slate-200">
            {statusLabel || "Processing..."}
          </div>
          <div className="mb-3 font-[var(--font-mono)] text-xs text-slate-500">
            {pct}% complete
          </div>

          {/* Progress bar */}
          <div className="mx-auto h-1.5 max-w-[280px] overflow-hidden rounded-full bg-slate-700/30">
            <div
              className="h-full rounded-full bg-sky-400 transition-all duration-500 ease-out"
              style={{ width: `${Math.max(pct, 5)}%` }}
            />
          </div>
        </>
      ) : (
        <>
          <div className="mb-3 text-4xl opacity-50">
            📡
          </div>
          <div className="mb-1.5 text-[15px] font-semibold text-slate-200">
            Drop QMDL2 file here
          </div>
          <div className="text-xs text-slate-500">
            Supports .qmdl2, .qmdl, .dlf, .qdb — or click to browse
          </div>
        </>
      )}
    </div>
  );
}
