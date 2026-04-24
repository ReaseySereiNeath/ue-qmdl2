"use client";

import { useEffect, useState } from "react";
import { getDiagnosis, type DiagnosisResponse } from "@/lib/api";

interface DiagnosticsPanelProps {
  jobId: string;
}

const SEVERITY_STYLES = {
  critical: {
    border: "border-red-500/20",
    bg: "bg-red-500/5",
    badge: "bg-red-500/15 text-red-400",
    dot: "bg-red-500",
    text: "text-red-400",
  },
  warning: {
    border: "border-amber-500/20",
    bg: "bg-amber-500/5",
    badge: "bg-amber-500/15 text-amber-400",
    dot: "bg-amber-500",
    text: "text-amber-400",
  },
  info: {
    border: "border-sky-500/20",
    bg: "bg-sky-500/5",
    badge: "bg-sky-500/15 text-sky-400",
    dot: "bg-sky-500",
    text: "text-sky-400",
  },
} as const;

function healthColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 50) return "#eab308";
  if (score >= 25) return "#f97316";
  return "#ef4444";
}

function healthLabel(score: number): string {
  if (score >= 80) return "Healthy";
  if (score >= 50) return "Degraded";
  if (score >= 25) return "Poor";
  return "Critical";
}

export function DiagnosticsPanel({ jobId }: DiagnosticsPanelProps) {
  const [report, setReport] = useState<DiagnosisResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedIssue, setExpandedIssue] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    getDiagnosis(jobId)
      .then((data) => {
        if (!cancelled) setReport(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [jobId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <div className="flex flex-col items-center gap-3">
          <svg
            className="h-8 w-8 animate-spin text-sky-500"
            viewBox="0 0 24 24"
            fill="none"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
            />
          </svg>
          <span className="font-[var(--font-mono)] text-xs text-slate-500">
            Running diagnostics...
          </span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 sm:p-6">
        <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
          Failed to load diagnostics: {error}
        </div>
      </div>
    );
  }

  if (!report) return null;

  const { healthScore, totalIssues, severityCounts, categoryCounts, issues } =
    report;

  return (
    <div className="flex flex-col gap-4 overflow-y-auto p-3 sm:gap-5 sm:p-5">
      {/* ── Health Score ── */}
      <div className="flex flex-col items-center gap-4 rounded-lg border border-slate-700/10 bg-slate-800/30 p-4 sm:flex-row sm:gap-6 sm:p-5">
        <div className="relative flex h-20 w-20 items-center justify-center sm:h-24 sm:w-24">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="none"
              stroke="rgba(100,116,139,0.15)"
              strokeWidth="8"
            />
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="none"
              stroke={healthColor(healthScore)}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${(healthScore / 100) * 264} 264`}
            />
          </svg>
          <div className="absolute flex flex-col items-center">
            <span
              className="font-[var(--font-mono)] text-2xl font-extrabold"
              style={{ color: healthColor(healthScore) }}
            >
              {healthScore}
            </span>
          </div>
        </div>

        <div className="flex flex-col gap-1 text-center sm:text-left">
          <div className="flex items-center justify-center gap-2 sm:justify-start">
            <span
              className="text-lg font-bold"
              style={{ color: healthColor(healthScore) }}
            >
              {healthLabel(healthScore)}
            </span>
          </div>
          <span className="text-xs text-slate-500">
            {totalIssues === 0
              ? "No issues detected in the log file."
              : `${totalIssues} issue${totalIssues > 1 ? "s" : ""} detected across ${Object.keys(categoryCounts).length} categor${Object.keys(categoryCounts).length > 1 ? "ies" : "y"}.`}
          </span>

          {/* Severity pills */}
          <div className="mt-2 flex flex-wrap justify-center gap-2 sm:justify-start">
            {(severityCounts.critical ?? 0) > 0 && (
              <span className="rounded-full bg-red-500/15 px-2.5 py-0.5 font-[var(--font-mono)] text-[11px] font-bold text-red-400">
                {severityCounts.critical} critical
              </span>
            )}
            {(severityCounts.warning ?? 0) > 0 && (
              <span className="rounded-full bg-amber-500/15 px-2.5 py-0.5 font-[var(--font-mono)] text-[11px] font-bold text-amber-400">
                {severityCounts.warning} warning
              </span>
            )}
            {(severityCounts.info ?? 0) > 0 && (
              <span className="rounded-full bg-sky-500/15 px-2.5 py-0.5 font-[var(--font-mono)] text-[11px] font-bold text-sky-400">
                {severityCounts.info} info
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Category Breakdown ── */}
      {Object.keys(categoryCounts).length > 0 && (
        <div className="rounded-lg border border-slate-700/10 bg-slate-800/30 p-4">
          <div className="mb-3 font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
            Issue Categories
          </div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(categoryCounts)
              .sort(([, a], [, b]) => b - a)
              .map(([cat, count]) => (
                <span
                  key={cat}
                  className="rounded border border-slate-700/20 bg-slate-700/10 px-2.5 py-1 font-[var(--font-mono)] text-[11px] text-slate-400"
                >
                  {cat}{" "}
                  <span className="font-bold text-slate-300">{count}</span>
                </span>
              ))}
          </div>
        </div>
      )}

      {/* ── Issues List ── */}
      {issues.length === 0 ? (
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-6 text-center">
          <div className="mb-2 text-3xl">&#x2705;</div>
          <div className="text-sm font-semibold text-emerald-400">
            All Clear
          </div>
          <div className="mt-1 text-xs text-slate-500">
            No problems detected in the UE diagnostic logs.
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <div className="font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
            Detected Issues ({issues.length})
          </div>

          {issues.map((issue) => {
            const style = SEVERITY_STYLES[issue.severity] || SEVERITY_STYLES.info;
            const isExpanded = expandedIssue === issue.id;

            return (
              <div
                key={issue.id}
                className={`rounded-lg border ${style.border} ${style.bg} transition-all duration-150`}
              >
                {/* Issue Header */}
                <button
                  type="button"
                  onClick={() =>
                    setExpandedIssue(isExpanded ? null : issue.id)
                  }
                  className="flex w-full cursor-pointer items-start gap-2 p-3 text-left sm:gap-3 sm:p-4"
                >
                  <div
                    className={`mt-1 h-2.5 w-2.5 flex-shrink-0 rounded-full ${style.dot}`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span
                        className={`font-[var(--font-mono)] text-xs font-bold ${style.text}`}
                      >
                        {issue.title}
                      </span>
                      <div className="flex items-center gap-2">
                        <span
                          className={`rounded px-1.5 py-0.5 font-[var(--font-mono)] text-[10px] font-bold ${style.badge}`}
                        >
                          {issue.count}x
                        </span>
                        <span className="rounded border border-slate-700/20 bg-slate-700/10 px-1.5 py-0.5 font-[var(--font-mono)] text-[10px] text-slate-500">
                          {issue.category}
                        </span>
                      </div>
                    </div>
                    <div className="mt-1 text-[11px] leading-relaxed text-slate-400">
                      {issue.description}
                    </div>
                  </div>
                  <span className="mt-1 flex-shrink-0 text-[10px] text-slate-600">
                    {isExpanded ? "▲" : "▼"}
                  </span>
                </button>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="border-t border-slate-700/10 px-3 py-3 sm:px-4">
                    {/* Recommendation */}
                    <div className="mb-3">
                      <div className="mb-1 font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-wider text-slate-600">
                        Recommendation
                      </div>
                      <div className="text-[11px] leading-relaxed text-sky-300">
                        {issue.recommendation}
                      </div>
                    </div>

                    {/* Time Range */}
                    <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
                      <div>
                        <span className="font-[var(--font-mono)] text-[10px] text-slate-600">
                          First seen:{" "}
                        </span>
                        <span className="font-[var(--font-mono)] text-[10px] text-slate-400">
                          {issue.firstSeen
                            ? new Date(issue.firstSeen).toLocaleString()
                            : "—"}
                        </span>
                      </div>
                      <div>
                        <span className="font-[var(--font-mono)] text-[10px] text-slate-600">
                          Last seen:{" "}
                        </span>
                        <span className="font-[var(--font-mono)] text-[10px] text-slate-400">
                          {issue.lastSeen
                            ? new Date(issue.lastSeen).toLocaleString()
                            : "—"}
                        </span>
                      </div>
                    </div>

                    {/* Affected logs count */}
                    <div className="mt-2">
                      <span className="font-[var(--font-mono)] text-[10px] text-slate-600">
                        Affected log entries:{" "}
                      </span>
                      <span className="font-[var(--font-mono)] text-[10px] font-bold text-slate-400">
                        {issue.affectedLogs.length}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
