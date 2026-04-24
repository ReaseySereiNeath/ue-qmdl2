// ─── Unified Log Schema ───

export type Severity = "info" | "warning" | "error" | "critical";

export type Protocol =
  | "NAS-5GS"
  | "NR-RRC"
  | "NR-MAC"
  | "NR-PDCP"
  | "NR-PHY"
  | "NR-ML1"
  | "LTE-RRC"
  | "LTE-NAS"
  | "LTE-MAC"
  | "LTE-ML1"
  | "SCAT-LOG";

export interface LogMetadata {
  arfcn?: number;
  rsrp?: number;
  sinr?: number;
  frameNumber?: number;
  frameLength?: number;
  gsmtapType?: string;
  gsmtapSubType?: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  timestampMs: number;
  protocol: Protocol | string;
  eventType: string;
  severity: Severity;
  message: string;
  details: Record<string, string>;
  metadata: LogMetadata;
  // Convenience fields extracted from details
  imsi: string;
  supi: string;
  gNBId: string;
  pci: number;
}

// ─── Filter State ───

export interface FilterState {
  search: string;
  protocols: string[];
  severities: Severity[];
  eventTypes: string[];
  imsi: string;
}

// ─── App State ───

export type ViewMode = "table" | "timeline" | "errors" | "diagnostics";
export type ParseStatus =
  | "idle"
  | "uploading"
  | "scat_decoding"
  | "tshark_parsing"
  | "normalizing"
  | "complete"
  | "error";

export interface AppState {
  logs: LogEntry[];
  filteredLogs: LogEntry[];
  filters: FilterState;
  selectedLog: LogEntry | null;
  isLoading: boolean;
  parseStatus: ParseStatus;
  errorMessage: string | null;
  jobId: string | null;
  progress: number;
  view: ViewMode;
}

// ─── Reducer Actions ───

export type AppAction =
  | { type: "SET_LOGS"; payload: LogEntry[] }
  | { type: "SET_FILTER"; payload: Partial<FilterState> }
  | { type: "SET_FILTERED_LOGS"; payload: LogEntry[] }
  | { type: "SELECT_LOG"; payload: LogEntry | null }
  | { type: "SET_LOADING"; payload: boolean }
  | { type: "SET_PARSE_STATUS"; payload: ParseStatus }
  | { type: "SET_ERROR"; payload: string | null }
  | { type: "SET_JOB"; payload: { jobId: string; progress: number; status: ParseStatus } }
  | { type: "SET_VIEW"; payload: ViewMode }
  | { type: "RESET" };

// ─── Diagnosis Types ───

export interface DiagnosisIssue {
  id: string;
  category: string;
  title: string;
  severity: "critical" | "warning" | "info";
  description: string;
  recommendation: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  affectedLogs: string[];
}

export interface DiagnosisReport {
  jobId: string;
  filename: string;
  healthScore: number;
  totalIssues: number;
  severityCounts: Record<string, number>;
  categoryCounts: Record<string, number>;
  issues: DiagnosisIssue[];
}

// ─── Anomaly Group ───

export interface AnomalyGroup {
  eventType: string;
  count: number;
  logs: LogEntry[];
  imsis: Set<string>;
}
