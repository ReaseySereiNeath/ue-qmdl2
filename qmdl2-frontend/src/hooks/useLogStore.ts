import { useReducer, useEffect, useCallback, useRef } from "react";
import type {
  AppState,
  AppAction,
  FilterState,
  LogEntry,
  ParseStatus,
  ViewMode,
} from "@/types/log";
import {
  uploadFile,
  getJobStatus,
  getLogs,
  type BackendLogEntry,
  type NasKeys,
} from "@/lib/api";

const initialState: AppState = {
  logs: [],
  filteredLogs: [],
  filters: {
    search: "",
    protocols: [],
    severities: [],
    eventTypes: [],
    imsi: "",
  },
  selectedLog: null,
  isLoading: false,
  parseStatus: "idle",
  errorMessage: null,
  jobId: null,
  progress: 0,
  view: "table",
};

function logReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_LOGS":
      return {
        ...state,
        logs: action.payload,
        filteredLogs: action.payload,
        isLoading: false,
        parseStatus: "complete",
        progress: 1,
      };
    case "SET_FILTER":
      return {
        ...state,
        filters: { ...state.filters, ...action.payload },
      };
    case "SET_FILTERED_LOGS":
      return { ...state, filteredLogs: action.payload };
    case "SELECT_LOG":
      return { ...state, selectedLog: action.payload };
    case "SET_LOADING":
      return { ...state, isLoading: action.payload };
    case "SET_PARSE_STATUS":
      return { ...state, parseStatus: action.payload };
    case "SET_ERROR":
      return {
        ...state,
        errorMessage: action.payload,
        isLoading: false,
        parseStatus: action.payload ? "error" : state.parseStatus,
      };
    case "SET_JOB":
      return {
        ...state,
        jobId: action.payload.jobId,
        progress: action.payload.progress,
        parseStatus: action.payload.status,
      };
    case "SET_VIEW":
      return { ...state, view: action.payload };
    case "RESET":
      return initialState;
    default:
      return state;
  }
}

/** Convert backend log entry to frontend LogEntry */
function toLogEntry(entry: BackendLogEntry): LogEntry {
  return {
    id: entry.id,
    timestamp: entry.timestamp,
    timestampMs: entry.timestampMs,
    protocol: entry.protocol,
    eventType: entry.eventType,
    severity: entry.severity as LogEntry["severity"],
    message: entry.message,
    details: entry.details || {},
    metadata: {
      arfcn: entry.metadata?.arfcn,
      frameNumber: entry.metadata?.frameNumber,
      gsmtapType: entry.metadata?.gsmtapType,
      gsmtapSubType: entry.metadata?.gsmtapSubType,
    },
    // Extract convenience fields from details
    imsi: entry.details?.imsi || "",
    supi: entry.details?.supi || "",
    gNBId: entry.details?.gNBId || "",
    pci: entry.details?.pci ? parseInt(entry.details.pci, 10) : 0,
  };
}

/** Map backend status string to frontend ParseStatus */
function mapStatus(status: string): ParseStatus {
  const map: Record<string, ParseStatus> = {
    queued: "uploading",
    scat_decoding: "scat_decoding",
    tshark_parsing: "tshark_parsing",
    normalizing: "normalizing",
    complete: "complete",
    error: "error",
  };
  return map[status] || "uploading";
}

function applyFilters(logs: LogEntry[], filters: FilterState): LogEntry[] {
  let result = logs;

  if (filters.search) {
    const q = filters.search.toLowerCase();
    result = result.filter(
      (l) =>
        l.imsi.includes(q) ||
        l.supi.toLowerCase().includes(q) ||
        l.message.toLowerCase().includes(q) ||
        l.eventType.toLowerCase().includes(q) ||
        l.protocol.toLowerCase().includes(q) ||
        l.gNBId.toLowerCase().includes(q)
    );
  }

  if (filters.protocols.length > 0) {
    result = result.filter((l) => filters.protocols.includes(l.protocol));
  }

  if (filters.severities.length > 0) {
    result = result.filter((l) => filters.severities.includes(l.severity));
  }

  if (filters.imsi) {
    result = result.filter((l) => l.imsi === filters.imsi);
  }

  return result;
}

export function useLogStore() {
  const [state, dispatch] = useReducer(logReducer, initialState);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  // Re-apply filters whenever logs or filters change
  useEffect(() => {
    const filtered = applyFilters(state.logs, state.filters);
    dispatch({ type: "SET_FILTERED_LOGS", payload: filtered });
  }, [state.logs, state.filters]);

  /** Poll job status until complete or error */
  const pollJob = useCallback(
    (jobId: string) => {
      if (pollingRef.current) clearInterval(pollingRef.current);

      pollingRef.current = setInterval(async () => {
        try {
          const job = await getJobStatus(jobId);
          const status = mapStatus(job.status);

          dispatch({
            type: "SET_JOB",
            payload: { jobId, progress: job.progress, status },
          });

          if (job.status === "complete") {
            if (pollingRef.current) clearInterval(pollingRef.current);
            // Fetch all logs
            const logsRes = await getLogs(jobId, { limit: 5000 });
            const logs = logsRes.logs.map(toLogEntry);
            dispatch({ type: "SET_LOGS", payload: logs });
          } else if (job.status === "error") {
            if (pollingRef.current) clearInterval(pollingRef.current);
            dispatch({
              type: "SET_ERROR",
              payload: job.error || "Processing failed",
            });
          }
        } catch {
          if (pollingRef.current) clearInterval(pollingRef.current);
          dispatch({
            type: "SET_ERROR",
            payload: "Lost connection to backend",
          });
        }
      }, 1000);
    },
    []
  );

  /** Upload file to backend and start polling */
  const handleFileUpload = useCallback(
    async (file: File, nasKeys?: NasKeys) => {
      dispatch({ type: "SET_LOADING", payload: true });
      dispatch({ type: "SET_PARSE_STATUS", payload: "uploading" });
      dispatch({ type: "SET_ERROR", payload: null });

      try {
        const res = await uploadFile(file, nasKeys);
        dispatch({
          type: "SET_JOB",
          payload: { jobId: res.jobId, progress: 0, status: "uploading" },
        });
        pollJob(res.jobId);
      } catch (err) {
        dispatch({
          type: "SET_ERROR",
          payload:
            err instanceof Error ? err.message : "Upload failed",
        });
      }
    },
    [pollJob]
  );

  const setFilter = useCallback((filter: Partial<FilterState>) => {
    dispatch({ type: "SET_FILTER", payload: filter });
  }, []);

  const selectLog = useCallback((log: LogEntry | null) => {
    dispatch({ type: "SELECT_LOG", payload: log });
  }, []);

  const setView = useCallback((view: ViewMode) => {
    dispatch({ type: "SET_VIEW", payload: view });
  }, []);

  const reset = useCallback(() => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    dispatch({ type: "RESET" });
  }, []);

  return {
    state,
    dispatch,
    handleFileUpload,
    setFilter,
    selectLog,
    setView,
    reset,
  };
}
