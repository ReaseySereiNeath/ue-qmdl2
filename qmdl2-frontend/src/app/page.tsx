"use client";

import { useRef, useState } from "react";
import { useLogStore } from "@/hooks/useLogStore";
import { FileUpload } from "@/components/FileUpload";
import { FilterPanel } from "@/components/FilterPanel";
import { LogTable } from "@/components/LogTable";
import { TimelineView } from "@/components/TimelineView";
import { ErrorPanel } from "@/components/ErrorPanel";
import { LogDetail } from "@/components/LogDetail";
import { StatsBar } from "@/components/StatsBar";
import { PipelineStatus } from "@/components/PipelineStatus";
import { DiagnosticsPanel } from "@/components/DiagnosticsPanel";
import type { ViewMode } from "@/types/log";

const VIEW_TABS: { id: ViewMode; label: string; icon: string }[] = [
  { id: "table", label: "Log Table", icon: "▤" },
  { id: "timeline", label: "Timeline", icon: "◇" },
  { id: "errors", label: "Anomalies", icon: "⚠" },
  { id: "diagnostics", label: "Diagnostics", icon: "⊕" },
];

export default function Home() {
  const {
    state,
    handleFileUpload,
    setFilter,
    selectLog,
    setView,
    reset,
  } = useLogStore();
  const headerFileRef = useRef<HTMLInputElement>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const {
    logs,
    filteredLogs,
    filters,
    selectedLog,
    isLoading,
    parseStatus,
    progress,
    view,
  } = state;

  const isReady = parseStatus === "complete";

  return (
    <div className="min-h-screen bg-[#060a14] text-slate-200">
      {/* ── Header ── */}
      <header
        className="sticky top-0 z-50 flex flex-wrap items-center justify-between gap-2 border-b border-slate-700/10 px-3 py-3 sm:px-6 sm:py-4"
        style={{
          background: "rgba(6,10,20,0.8)",
          backdropFilter: "blur(20px)",
        }}
      >
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Mobile sidebar toggle */}
          {isReady && logs.length > 0 && (
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="flex h-8 w-8 cursor-pointer items-center justify-center rounded-md border border-slate-700/20 bg-slate-700/10 text-slate-400 lg:hidden"
            >
              {sidebarOpen ? "✕" : "☰"}
            </button>
          )}
          <div
            className="flex h-8 w-8 items-center justify-center rounded-md font-[var(--font-mono)] text-sm font-extrabold text-white"
            style={{
              background:
                "linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%)",
            }}
          >
            Q2
          </div>
          <div>
            <div className="text-sm font-bold tracking-tight">
              QMDL2 Log Viewer
            </div>
            <div className="hidden font-[var(--font-mono)] text-[10px] text-slate-600 sm:block">
              SCAT Hybrid Decoder — v0.1.0
            </div>
          </div>
        </div>

        {isReady && <StatsBar logs={filteredLogs} />}

        <div className="flex items-center gap-1.5">
          {isReady && (
            <>
              <input
                ref={headerFileRef}
                type="file"
                accept=".qmdl2,.qmdl,.dlf,.qdb"
                hidden
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    reset();
                    handleFileUpload(file);
                  }
                  e.target.value = "";
                }}
              />
              <button
                onClick={() => headerFileRef.current?.click()}
                className="cursor-pointer rounded border border-sky-500/20 bg-sky-500/10 px-2.5 py-1 font-[var(--font-mono)] text-[10px] font-semibold text-sky-400 transition-colors hover:bg-sky-500/20"
              >
                Upload New File
              </button>
              <span className="hidden items-center gap-1 rounded border border-emerald-500/20 bg-emerald-500/8 px-2.5 py-1 font-[var(--font-mono)] text-[10px] font-semibold text-emerald-500 sm:inline-flex">
                ● Parsed
              </span>
            </>
          )}
          <span className="hidden rounded border border-slate-700/20 bg-slate-700/10 px-2.5 py-1 font-[var(--font-mono)] text-[10px] text-slate-500 md:inline">
            Backend: SCAT {">>"} PCAP {">>"} JSON
          </span>
        </div>
      </header>

      {/* ── Upload Screen ── */}
      {!isReady && (
        <div className="animate-fade-up mx-auto max-w-xl px-4 pt-12 sm:px-6 sm:pt-20">
          <div className="mb-8 text-center">
            <h1 className="mb-2 text-2xl font-extrabold tracking-tight sm:text-3xl">
              Analyze 5G Diagnostic Logs
            </h1>
            <p className="text-sm leading-relaxed text-slate-500">
              Upload a QMDL2 file from your Qualcomm device. The backend
              decodes it using SCAT into structured JSON for visualization.
            </p>
          </div>

          <FileUpload
            onFileParsed={handleFileUpload}
            isLoading={isLoading}
            progress={progress}
            parseStatus={parseStatus}
          />

          <div className="mt-5 text-center text-xs text-slate-600">
            Supports .qmdl2, .qmdl, .dlf, .qdb files
          </div>

          {isLoading && parseStatus !== "idle" && parseStatus !== "error" && (
            <PipelineStatus currentStatus={parseStatus} />
          )}

          {parseStatus === "error" && state.errorMessage && (
            <div className="mt-5 rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-center text-sm text-red-400">
              {state.errorMessage}
            </div>
          )}
        </div>
      )}

      {/* ── No Logs Found ── */}
      {isReady && logs.length === 0 && (
        <div className="mx-auto max-w-md px-4 pt-16 text-center sm:px-6 sm:pt-24">
          <div className="mb-4 text-5xl opacity-40">📭</div>
          <h2 className="mb-2 text-xl font-bold text-slate-200">
            No decoded logs found
          </h2>
          <p className="mb-6 text-sm leading-relaxed text-slate-500">
            The file was processed successfully, but SCAT did not produce any
            decodable packets. This can happen if the QMDL2 file is empty,
            corrupted, or contains only unsupported message types.
          </p>
          <button
            onClick={() => {
              reset();
              headerFileRef.current?.click();
            }}
            className="cursor-pointer rounded-lg border border-sky-500/20 bg-sky-500/10 px-5 py-2.5 text-sm font-semibold text-sky-400 transition-colors hover:bg-sky-500/20"
          >
            Try Another File
          </button>
        </div>
      )}

      {/* ── Dashboard ── */}
      {isReady && logs.length > 0 && (
        <div className="flex flex-col lg:flex-row" style={{ height: "calc(100dvh - 57px)" }}>
          {/* Mobile sidebar overlay */}
          {sidebarOpen && (
            <div
              className="fixed inset-0 z-40 bg-black/50 lg:hidden"
              onClick={() => setSidebarOpen(false)}
            />
          )}

          {/* Sidebar */}
          <aside
            className={`fixed inset-y-0 left-0 z-50 w-[260px] flex-col gap-4 overflow-y-auto border-r border-slate-700/10 bg-[#060a14] p-4 transition-transform duration-200 lg:relative lg:z-auto lg:flex lg:translate-x-0 lg:bg-[#060a14]/50 ${sidebarOpen ? "flex translate-x-0" : "hidden -translate-x-full"}`}
            style={{ top: 0 }}
          >
            {/* Close button for mobile */}
            <div className="flex items-center justify-between lg:hidden">
              <span className="font-[var(--font-mono)] text-xs font-bold text-slate-400">Filters</span>
              <button
                onClick={() => setSidebarOpen(false)}
                className="cursor-pointer text-lg text-slate-500 hover:text-slate-300"
              >
                ✕
              </button>
            </div>

            {/* View Tabs */}
            <div className="flex flex-col gap-0.5">
              {VIEW_TABS.map((t) => (
                <div
                  key={t.id}
                  onClick={() => {
                    setView(t.id);
                    setSidebarOpen(false);
                  }}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-2 text-xs font-semibold transition-all duration-150"
                  style={{
                    background:
                      view === t.id
                        ? "rgba(56,189,248,0.08)"
                        : "transparent",
                    color: view === t.id ? "#38bdf8" : "#64748b",
                  }}
                >
                  <span className="text-sm">{t.icon}</span>
                  {t.label}
                </div>
              ))}
            </div>

            <div className="h-px bg-slate-700/10" />

            <FilterPanel
              filters={filters}
              logs={logs}
              onFilterChange={setFilter}
            />
          </aside>

          {/* Mobile view tabs (horizontal) */}
          <div className="flex shrink-0 gap-1 overflow-x-auto border-b border-slate-700/10 px-3 py-2 lg:hidden">
            {VIEW_TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setView(t.id)}
                className="flex shrink-0 cursor-pointer items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all duration-150"
                style={{
                  background:
                    view === t.id
                      ? "rgba(56,189,248,0.08)"
                      : "transparent",
                  color: view === t.id ? "#38bdf8" : "#64748b",
                }}
              >
                <span className="text-sm">{t.icon}</span>
                {t.label}
              </button>
            ))}
          </div>

          {/* Main Content */}
          <main className="flex min-h-0 min-w-0 flex-1 flex-col">
            {view === "table" && (
              <LogTable
                logs={filteredLogs}
                selectedLog={selectedLog}
                onSelectLog={selectLog}
              />
            )}

            {view === "timeline" && (
              <div className="overflow-y-auto p-3 sm:p-5">
                <TimelineView logs={filteredLogs} />
                <div className="mt-6">
                  <LogTable
                    logs={filteredLogs}
                    selectedLog={selectedLog}
                    onSelectLog={selectLog}
                  />
                </div>
              </div>
            )}

            {view === "errors" && (
              <div className="overflow-y-auto p-3 sm:p-5">
                <ErrorPanel logs={filteredLogs} />
                <div className="mt-5">
                  <LogTable
                    logs={filteredLogs.filter(
                      (l) =>
                        l.severity === "error" || l.severity === "critical"
                    )}
                    selectedLog={selectedLog}
                    onSelectLog={selectLog}
                  />
                </div>
              </div>
            )}

            {view === "diagnostics" && state.jobId && (
              <DiagnosticsPanel jobId={state.jobId} />
            )}
          </main>

          {/* Detail Drawer */}
          {selectedLog && (
            <LogDetail
              log={selectedLog}
              onClose={() => selectLog(null)}
            />
          )}
        </div>
      )}
    </div>
  );
}
