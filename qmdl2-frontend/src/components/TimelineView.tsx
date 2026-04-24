"use client";

import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { LogEntry } from "@/types/log";

interface TimelineViewProps {
  logs: LogEntry[];
}

interface BucketData {
  time: number;
  info: number;
  warning: number;
  error: number;
  critical: number;
  total: number;
}

export function TimelineView({ logs }: TimelineViewProps) {
  const timelineData = useMemo((): BucketData[] => {
    if (logs.length === 0) return [];
    const bucketMs = 30000; // 30s buckets
    const minT = logs[0].timestampMs;
    const buckets: Record<number, BucketData> = {};

    logs.forEach((log) => {
      const bucketKey = Math.floor((log.timestampMs - minT) / bucketMs);
      if (!buckets[bucketKey]) {
        buckets[bucketKey] = {
          time: (bucketKey * bucketMs) / 1000,
          info: 0,
          warning: 0,
          error: 0,
          critical: 0,
          total: 0,
        };
      }
      buckets[bucketKey][log.severity]++;
      buckets[bucketKey].total++;
    });

    return Object.values(buckets).sort((a, b) => a.time - b.time);
  }, [logs]);

  return (
    <div className="px-1">
      <div className="mb-2.5 font-[var(--font-mono)] text-[10px] font-bold uppercase tracking-widest text-slate-600">
        Event Distribution Over Time (30s buckets)
      </div>
      <div className="h-[160px] sm:h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={timelineData} barCategoryGap={2}>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 10, fill: "#475569" }}
              tickFormatter={(v: number) => `${Math.floor(v / 60)}m`}
              axisLine={{ stroke: "rgba(148,163,184,0.1)" }}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 10, fill: "#475569" }}
              axisLine={false}
              tickLine={false}
              width={30}
            />
            <Tooltip
              contentStyle={{
                background: "#0f172a",
                border: "1px solid rgba(148,163,184,0.15)",
                borderRadius: 6,
                fontSize: 11,
              }}
              labelFormatter={(v) =>
                `T+${Math.floor(Number(v) / 60)}m ${Math.floor(Number(v) % 60)}s`
              }
            />
            <Bar dataKey="info" stackId="a" fill="#38bdf8" />
            <Bar dataKey="warning" stackId="a" fill="#fbbf24" />
            <Bar dataKey="error" stackId="a" fill="#f87171" />
            <Bar
              dataKey="critical"
              stackId="a"
              fill="#ef4444"
              radius={[2, 2, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
